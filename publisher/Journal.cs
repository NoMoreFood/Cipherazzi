using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Cipherazzi.Data;

namespace Cipherazzi.Publisher;

internal sealed record Position(long Revision, int Kind, string Key);
internal sealed record JournalBatch(Position Next, long Acknowledged, List<PublishedEvent> Events, bool More);
internal sealed record PublishedEvent(Position Position, string Computer, long Timestamp, string Json,
    int Severity, string HealthStatus, long Losses)
{
    public int EventKind { get; init; } = Position.Kind;
    public bool EmitSnapshot { get; init; } = true;
    public List<PublishedEvent> Alerts { get; init; } = [];
}

internal sealed class Journal(string path, string destination, PolicyEvaluator? policies = null, string policyResults = "all")
{
    private readonly string target = Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes("publishing|" + destination)));
    public string DatabaseId { get; private set; } = "";
    public Position Cursor { get; private set; } = new(0, 0, "");
    public string LockName => "Global\\Cipherazzi.Publisher." + DatabaseId + "." + target;
    private const int BatchSize = 128;

    private SqliteConnection Open(bool write)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = write ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
            Pooling = false, Cache = SqliteCacheMode.Private, DefaultTimeout = 2
        }.ToString());
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA application_id";
            if (Convert.ToInt64(command.ExecuteScalar()) != 0x435A5A49)
                throw new InvalidDataException("Choose a journal created by the Cipherazzi collector.");
            command.CommandText = "PRAGMA trusted_schema=OFF";
            command.ExecuteNonQuery();
            command.CommandText = "SELECT schema_version,database_id FROM metadata WHERE id=1";
            using var reader = command.ExecuteReader();
            if (!reader.Read() || reader.GetInt32(0) != 4)
                throw new InvalidDataException("Unsupported Cipherazzi journal schema.");
            if (DatabaseId.Length > 0 && DatabaseId != reader.GetString(1))
                throw new InvalidDataException(
                    "The capture journal identity changed; restart with the intended journal.");
            DatabaseId = reader.GetString(1);
            if (!Guid.TryParse(DatabaseId, out _))
                throw new InvalidDataException("The journal identity is invalid.");
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    public void Identify()
    {
        using var connection = Open(false);
    }

    public void Register(bool startNow)
    {
        // Register before opening an output so retention also protects an unavailable destination.
        using var connection = Open(true);
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS replication_consumers (
                target_id TEXT PRIMARY KEY, acknowledged_revision INTEGER NOT NULL CHECK(acknowledged_revision>=0),
                updated_us INTEGER NOT NULL) STRICT;
            CREATE TABLE IF NOT EXISTS publishing_cursors (
                target_id TEXT PRIMARY KEY, database_id TEXT NOT NULL, revision INTEGER NOT NULL,
                kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 4), event_key TEXT NOT NULL) STRICT;
            INSERT OR IGNORE INTO publishing_cursors
                SELECT @target,database_id,CASE WHEN @now THEN revision ELSE 0 END,
                    CASE WHEN @now THEN 4 ELSE 0 END,'' FROM metadata WHERE id=1;
            INSERT OR IGNORE INTO replication_consumers
                SELECT target_id,CASE WHEN kind=4 THEN revision ELSE max(0,revision-1) END,@time
                FROM publishing_cursors WHERE target_id=@target;
            """;
        command.Parameters.AddWithValue("@target", target);
        command.Parameters.AddWithValue("@now", startNow);
        command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
        command.ExecuteNonQuery();
        command.CommandText =
            "SELECT database_id,revision,kind,event_key FROM publishing_cursors WHERE target_id=@target";
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read() || reader.GetString(0) != DatabaseId)
                throw new InvalidDataException("The publishing cursor belongs to a different journal.");
            Cursor = new(reader.GetInt64(1), reader.GetInt32(2), reader.GetString(3));
        }
        transaction.Commit();
    }

    public void Unregister()
    {
        using var connection = Open(true);
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT count(*) FROM sqlite_schema WHERE name='publishing_cursors'";
        if (Convert.ToInt64(command.ExecuteScalar()) != 0)
        {
            command.CommandText = "DELETE FROM publishing_cursors WHERE target_id=@target";
            command.Parameters.AddWithValue("@target", target);
            command.ExecuteNonQuery();
            command.CommandText = "DELETE FROM replication_consumers WHERE target_id=@target";
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    public JournalBatch Read(EventKinds kinds, CancellationToken cancellation)
    {
        using var connection = Open(false);
        SQLitePCL.raw.sqlite3_progress_handler(connection.Handle, 1000,
            _ => cancellation.IsCancellationRequested ? 1 : 0, null);
        using var transaction = connection.BeginTransaction(deferred: true);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT revision FROM metadata WHERE id=1";
        var available = Convert.ToInt64(command.ExecuteScalar());
        if (available < Cursor.Revision)
            throw new InvalidDataException("The source journal was rolled back; use a new journal.");
        if (available == Cursor.Revision && Cursor.Kind == 4)
            return new(Cursor, available, [], false);

        // Page within a revision, keeping incomplete revisions protected without holding a read during delivery.
        var evaluate = policies is not null && kinds.HasFlag(EventKinds.Policies);
        var certificateFacts = evaluate ? PolicyEvaluator.CertificateFactsSql(DatabaseSource.Sqlite(path)) : "NULL";
        var associated = evaluate ? """
            CASE WHEN json_valid(c.detail_json) THEN EXISTS (SELECT 1 FROM connections linked
                WHERE linked.run_id=json_extract(c.detail_json,'$.matched_run_id')
                    AND linked.flow_id=json_extract(c.detail_json,'$.matched_flow_id')) ELSE 0 END
            """ : "0";
        var connectionMetadata = evaluate ? "c.crypto_json" : "substr(c.crypto_json,1,65537)";
        var endpointMetadata = evaluate ? "c.detail_json" : "substr(c.detail_json,1,65537)";
        var events = new List<PublishedEvent>(BatchSize * 3);
        foreach (var (kind, table, key, time, selected) in new[]
        {
            (1, "connections", "printf('%020d',c.id)", "c.last_us", $"""
                c.run_id,c.flow_id,c.first_us,c.last_us,c.source_address,c.source_port,
                c.destination_address,c.destination_port,c.tls_version,c.tls_name AS protocol,
                c.cipher_id,c.cipher_name,c.sni,c.selected_alpn,c.state,c.group_name,c.key_exchange,c.encryption,
                c.key_bits,c.authentication,c.certificate_sha256,c.alert,c.ended_us,c.close_reason,
                c.source_pid,c.source_process,c.source_path,c.destination_pid,c.destination_process,c.destination_path,
                c.id AS policy_observation_id,c.ech_offered AS policy_ech_offered,c.tls_name AS policy_protocol,
                {certificateFacts} AS policy_certificate_facts,{connectionMetadata} AS metadata_json
                """),
            (2, "endpoint_events", "c.id", "c.timestamp_us", $"""
                c.run_id,c.id,c.provider,c.kind,c.result,c.pid,c.peer,c.port,c.protocol,c.cipher,c.certificate_id,
                {associated} AS policy_associated,{endpointMetadata} AS metadata_json
                """),
            (3, "capture_sessions", "c.id", "c.updated_us", """
                c.id AS run_id,c.source,c.process_status,c.status,c.started_us,c.stopped_us,c.packets,c.bytes,
                c.capture_lost,c.queue_lost,c.storage_lost,c.process_events_lost,c.telemetry_lost,
                c.truncated,c.malformed,c.unsupported,c.flow_limit,c.reassembly_limit,c.active_flows,c.buffered_bytes
                """)
        })
        {
            if (((int)kinds & (1 << (kind - 1))) == 0 && !(evaluate && kind is 1 or 2))
                continue;
            cancellation.ThrowIfCancellationRequested();
            var computer = kind == 3 ? "c.computer_name" : "s.computer_name";
            var join = kind == 3 ? "" : " JOIN capture_sessions s ON s.id=c.run_id";
            var order = kind == 1 ? "c.id" : key;
            var boundary = kind < Cursor.Kind ? "c.change_revision>@after" : kind > Cursor.Kind ?
                "c.change_revision>=@after" : $"(c.change_revision,{order})>(@after,@key)";
            command.CommandText = $"""
                SELECT c.change_revision AS revision,{key} AS event_key,{time} AS timestamp_us,
                    {computer} AS computer,{selected}
                FROM {table} c{join}
                WHERE {boundary} AND c.change_revision<=@upper
                ORDER BY c.change_revision,{order} LIMIT {BatchSize + 1}
                """;
            command.Parameters.Clear();
            command.Parameters.AddWithValue("@after", Cursor.Revision);
            command.Parameters.AddWithValue("@upper", available);
            command.Parameters.AddWithValue("@key", kind == 1 && Cursor.Kind == 1 ?
                long.Parse(Cursor.Key, System.Globalization.CultureInfo.InvariantCulture) : (object)Cursor.Key);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                cancellation.ThrowIfCancellationRequested();
                var value = Serialize(reader, kind);
                if (evaluate && kind is 1 or 2)
                {
                    // Evaluate the same committed snapshot as the exported metadata before releasing the read.
                    var flow = kind == 1 ? PolicyEvaluator.ConnectionEvidence(reader, value.Computer) :
                        Convert.ToInt32(reader["policy_associated"]) == 0 ?
                            PolicyEvaluator.EndpointEvidence(reader.GetString(reader.FieldCount - 1),
                                value.Computer, value.Position.Key, reader.GetString(reader.GetOrdinal("run_id"))) : null;
                    if (flow is not null)
                        value = value with { Alerts = PolicyAlerts(value, flow) };
                }
                events.Add(value with { EmitSnapshot = ((int)kinds & (1 << (kind - 1))) != 0 });
            }
        }
        events.Sort((left, right) =>
        {
            var value = left.Position.Revision.CompareTo(right.Position.Revision);
            if (value == 0)
                value = left.Position.Kind.CompareTo(right.Position.Kind);
            return value == 0 ? string.CompareOrdinal(left.Position.Key, right.Position.Key) : value;
        });
        var more = events.Count > BatchSize;
        if (more)
            events.RemoveRange(BatchSize, events.Count - BatchSize);
        var next = more ? events[^1].Position : new(available, 4, "");
        transaction.Commit();
        return new(next, more ? next.Revision - 1 : available, events, more);
    }

    public void Advance(JournalBatch batch)
    {
        using var connection = Open(true);
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE publishing_cursors SET revision=@revision,kind=@kind,event_key=@key
            WHERE target_id=@target AND revision=@previous AND kind=@previousKind AND event_key=@previousKey;
            """;
        command.Parameters.AddWithValue("@target", target);
        command.Parameters.AddWithValue("@revision", batch.Next.Revision);
        command.Parameters.AddWithValue("@kind", batch.Next.Kind);
        command.Parameters.AddWithValue("@key", batch.Next.Key);
        command.Parameters.AddWithValue("@previous", Cursor.Revision);
        command.Parameters.AddWithValue("@previousKind", Cursor.Kind);
        command.Parameters.AddWithValue("@previousKey", Cursor.Key);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidDataException("The publishing cursor changed concurrently; restart this publisher.");
        command.CommandText = """
            UPDATE replication_consumers SET acknowledged_revision=max(acknowledged_revision,@ack),updated_us=@time
            WHERE target_id=@target;
            """;
        command.Parameters.AddWithValue("@ack", batch.Acknowledged);
        command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
        if (command.ExecuteNonQuery() != 1)
            throw new InvalidDataException("The destination's retention protection was removed.");
        transaction.Commit();
        Cursor = batch.Next;
    }

    private PublishedEvent Serialize(SqliteDataReader reader, int kind)
    {
        var position = new Position(reader.GetInt64(0), kind, reader.GetString(1));
        var timestamp = reader.GetInt64(2);
        var computer = reader.IsDBNull(3) ? "" : reader.GetString(3);
        var truncated = computer.Length > 256;
        var payload = new Dictionary<string, object?>();
        for (var index = 4; index < reader.FieldCount; index++)
        {
            if (reader.GetName(index) == "metadata_json" ||
                reader.GetName(index).StartsWith("policy_", StringComparison.Ordinal))
                continue;
            var value = reader.IsDBNull(index) ? null : reader.GetValue(index);
            truncated |= value is string field && field.Length > 1024;
            payload[reader.GetName(index)] = value is string text ? text[..Math.Min(text.Length, 1024)] : value;
        }
        if (kind != 3)
        {
            // Publish selected public evidence, excluding large provider XML, certificate bytes, and raw report bodies.
            var metadata = reader.GetString(reader.FieldCount - 1);
            if (metadata.Length <= 65536)
            {
                try
                {
                    using var document = JsonDocument.Parse(metadata, new JsonDocumentOptions { MaxDepth = 32 });
                    var evidence = new Dictionary<string, JsonElement>();
                    foreach (var name in new[]
                    {
                        "group_class", "group_status", "signature", "signature_class", "dh_bits", "transport",
                        "quic", "dtls_version", "success", "peer_verified", "selected_alpn", "group_id",
                        "signature_scheme", "local_signature_scheme", "confirmation", "endpoint_confirmations",
                        "local", "remote", "role", "process_started_us", "handshake_started_us", "operation_started_us",
                        "algorithm", "mode", "key_bits", "correlation"
                    })
                    {
                        if (!document.RootElement.TryGetProperty(name, out var value))
                            continue;
                        if (value.GetRawText().Length <= 2048)
                            evidence[name] = value.Clone();
                        else
                            truncated = true;
                    }
                    payload["evidence"] = evidence;
                }
                catch (Exception error) when (error is JsonException or InvalidOperationException)
                {
                    payload["metadata_unavailable"] = true;
                }
            }
            else
            {
                payload["metadata_unavailable"] = true;
                truncated = true;
            }
        }
        var type = kind switch { 1 => "connection", 2 => "endpoint", _ => "health" };
        var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{DatabaseId}|{position.Revision}|{kind}|{position.Key}")));
        var envelope = new Dictionary<string, object?>
        {
            ["schema"] = "cipherazzi.event/1", ["id"] = id, ["database_id"] = DatabaseId,
            ["revision"] = position.Revision, ["type"] = type, ["timestamp_us"] = timestamp,
            ["computer"] = computer[..Math.Min(computer.Length, 256)], ["payload"] = payload
        };
        if (truncated)
            envelope["truncated"] = true;
        var json = JsonSerializer.Serialize(envelope);
        if (Encoding.UTF8.GetByteCount(json) > 16384)
        {
            payload.Remove("evidence");
            foreach (var key in payload.Keys.ToArray())
                if (payload[key] is string value && value.Length > 128)
                    payload[key] = value[..128];
            envelope["truncated"] = true;
            json = JsonSerializer.Serialize(envelope);
        }
        if (Encoding.UTF8.GetByteCount(json) > 16384)
            throw new InvalidDataException("Published metadata exceeded the bounded event size.");
        var losses = kind != 3 ? 0 : new[]
        {
            "capture_lost", "queue_lost", "storage_lost", "process_events_lost", "telemetry_lost",
            "truncated", "flow_limit", "reassembly_limit"
        }.Sum(name => Convert.ToInt64(payload[name]));
        var status = kind == 3 ? payload["status"]?.ToString() ?? "" : "";
        var severity = losses > 0 || status.StartsWith("failed", StringComparison.Ordinal) ? 4 : 6;
        if (kind == 2 && payload["result"]?.ToString()?.Contains("failure", StringComparison.OrdinalIgnoreCase) == true)
            severity = 4;
        return new(position, computer, timestamp, json, severity, status, losses);
    }

    private List<PublishedEvent> PolicyAlerts(PublishedEvent snapshot, FlowEvidence flow)
    {
        var alerts = new List<PublishedEvent>();
        foreach (var result in policies!.Evaluate(flow))
        {
            if (policyResults == "violations" && result.Status != "Violation" ||
                policyResults == "nonpassing" && result.Status == "Pass")
                continue;

            // One bounded event per policy preserves every result and supports receiver deduplication after retries.
            var truncated = false;
            string Clip(string value, int maximum = 1024)
            {
                truncated |= value.Length > maximum;
                return value[..Math.Min(value.Length, maximum)];
            }
            var payload = new Dictionary<string, object?>
            {
                ["observation_id"] = flow.Id, ["run_id"] = Clip(flow.RunId), ["flow_id"] = flow.FlowId,
                ["endpoint_event_id"] = Clip(flow.EndpointEventId),
                ["policy"] = Clip(result.Name), ["status"] = result.Status,
                ["protocol"] = flow.Protocol, ["evidence_source"] = flow.EvidenceSource,
                ["server"] = Clip(flow.ServerName), ["client_process"] = Clip(flow.ClientPath.Length > 0 ?
                    flow.ClientPath : flow.ClientProcess), ["server_process"] = Clip(flow.ServerPath.Length > 0 ?
                    flow.ServerPath : flow.ServerProcess),
                ["emitting_process"] = Clip(flow.EndpointPath.Length > 0 ? flow.EndpointPath : flow.EndpointProcess),
                ["issue_count"] = result.Issues.Count,
                ["issues"] = result.Issues.Take(16)
                    .Select(issue => new { status = issue.Status, message = Clip(issue.Message, 256) }).ToArray()
            };
            truncated |= result.Issues.Count > 16;
            var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{DatabaseId}|{snapshot.Position.Revision}|{snapshot.Position.Kind}|{snapshot.Position.Key}|" +
                $"{policies.Fingerprint}|{result.Name}")));
            var envelope = new Dictionary<string, object?>
            {
                ["schema"] = "cipherazzi.event/1", ["id"] = id, ["database_id"] = DatabaseId,
                ["revision"] = snapshot.Position.Revision, ["type"] = "policy", ["timestamp_us"] = snapshot.Timestamp,
                ["computer"] = Clip(snapshot.Computer, 256), ["payload"] = payload, ["truncated"] = truncated
            };
            var json = JsonSerializer.Serialize(envelope);
            if (Encoding.UTF8.GetByteCount(json) > 16384)
            {
                foreach (var key in payload.Keys.ToArray())
                    if (payload[key] is string text)
                        payload[key] = Clip(text, 128);
                payload["issues"] = result.Issues.Take(16)
                    .Select(issue => new { status = issue.Status, message = Clip(issue.Message, 64) }).ToArray();
                envelope["truncated"] = true;
                json = JsonSerializer.Serialize(envelope);
            }
            if (Encoding.UTF8.GetByteCount(json) > 16384)
                throw new InvalidDataException("Published policy metadata exceeded the bounded event size.");
            alerts.Add(snapshot with
            {
                Json = json, Severity = result.Status == "Pass" ? 6 : 4, EventKind = 4, Alerts = []
            });
        }
        return alerts;
    }
}
