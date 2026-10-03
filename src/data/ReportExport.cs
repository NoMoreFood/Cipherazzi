using System.Data.Common;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Cipherazzi.Data;

public enum ReportKind { Connections, Endpoints, Policies }

public static class ReportExport
{
    public static long Write(DatabaseSource source, Query query, ReportKind kind, string path,
        IReadOnlyList<CryptoPolicy> policies, CancellationToken cancellation, IProgress<long>? progress = null)
    {
        query.Validate(kind == ReportKind.Endpoints ?
            InvestigationTarget.Endpoints : InvestigationTarget.Connections);
        if (!Enum.IsDefined(kind))
            throw new ArgumentException("Choose a supported report kind.");
        var target = Path.GetFullPath(path);
        var extension = Path.GetExtension(target);
        var csv = extension.Equals(".csv", StringComparison.OrdinalIgnoreCase);
        void CheckTarget()
        {
            // Database headers also protect journals reached through a directory alias or another path spelling.
            var unsupported = !csv && !extension.Equals(".jsonl", StringComparison.OrdinalIgnoreCase);
            var database = source.Provider == DatabaseProvider.Sqlite &&
                target.Equals(source.FilePath, StringComparison.OrdinalIgnoreCase);
            if (!unsupported && !database && File.Exists(target))
            {
                using var existing = File.OpenRead(target);
                Span<byte> header = stackalloc byte[16];
                database = existing.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) == header.Length &&
                    header.SequenceEqual("SQLite format 3\0"u8);
            }
            if (unsupported || database)
                throw new ArgumentException("Choose a CSV or JSONL report file separate from the capture journal.");
        }
        CheckTarget();
        var evaluator = kind == ReportKind.Policies ? new PolicyEvaluator(policies) : null;
        var temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var count = 0L;
        string[]? headings = null;

        // Stream the requested evidence to a temporary file; cancellation and errors preserve an existing report.
        try
        {
            using (var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult())
            {
                source.Validate(connection, cancellation);

                // Keep every table read in the same evidence snapshot, including rows arriving during publication.
                using var transaction = source.BeginRead(connection, cancellation);
                using var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                    65536, FileOptions.SequentialScan);
                using var writer = new StreamWriter(file, new UTF8Encoding(csv), 65536);
                void Header(IEnumerable<string> columns)
                {
                    if (headings is not null)
                        return;
                    headings = columns.ToArray();
                    if (csv)
                        writer.WriteLine(string.Join(',', headings.Select(name => Quote(name))));
                }
                void Row(Dictionary<string, object?> values)
                {
                    cancellation.ThrowIfCancellationRequested();
                    Header(values.Keys);
                    if (csv)
                        writer.WriteLine(string.Join(',', headings!.Select(name =>
                            values.GetValueOrDefault(name) is { } value ?
                                Quote(Text(value), value is string) : "\"\"")));
                    else
                        writer.WriteLine(JsonSerializer.Serialize(values));
                    if (++count % 128 == 0)
                        progress?.Report(count);
                }
                DbCommand Command(string sql)
                {
                    var command = connection.CreateCommand();
                    command.Transaction = transaction;
                    command.CommandTimeout = 60;
                    command.CommandText = sql;
                    return command;
                }
                void Records(bool endpoint)
                {
                    using var command = Command("");
                    var where = endpoint ? InvestigationSql.EndpointWhere(source, query, command) :
                        ObservationSql.Where(source, query, command);
                    var table = endpoint ? "endpoint_events e" : "connections c";
                    var alias = endpoint ? "e" : "c";
                    var time = endpoint ? "timestamp_us" : "first_us";
                    command.CommandText = $"""
                        SELECT {alias}.*,s.computer_name FROM {source.Prefix}{table}
                        JOIN {source.Prefix}capture_sessions s ON s.id={alias}.run_id
                        WHERE {where} ORDER BY {alias}.{time},{alias}.id
                        """;
                    using var registration = cancellation.Register(command.Cancel);
                    using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
                    Header(Enumerable.Range(0, reader.FieldCount).Select(reader.GetName));
                    while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
                    {
                        var values = new Dictionary<string, object?>();
                        for (var index = 0; index < reader.FieldCount; index++)
                            values[reader.GetName(index)] = reader.IsDBNull(index) ? null : reader.GetValue(index);
                        Row(values);
                    }
                }
                void Assessment(FlowEvidence flow)
                {
                    foreach (var result in evaluator!.Evaluate(flow))
                        Row(new()
                        {
                            ["observation_id"] = flow.Id,
                            ["run_id"] = flow.RunId,
                            ["flow_id"] = flow.FlowId,
                            ["endpoint_event_id"] = flow.EndpointEventId,
                            ["first_us"] = flow.FirstUs,
                            ["computer"] = flow.Computer,
                            ["client_process"] = flow.ClientProcess,
                            ["client_path"] = flow.ClientPath,
                            ["server_process"] = flow.ServerProcess,
                            ["server_path"] = flow.ServerPath,
                            ["server"] = flow.ServerName,
                            ["protocol"] = flow.Protocol,
                            ["transport"] = flow.Transport,
                            ["evidence_source"] = flow.EvidenceSource,
                            ["policy"] = result.Name,
                            ["status"] = result.Status,
                            ["issues"] = result.Issues.Select(issue =>
                                new { status = issue.Status, message = issue.Message }).ToArray()
                        });
                }
                if (kind != ReportKind.Policies)
                    Records(kind == ReportKind.Endpoints);
                else
                {
                    Header(["observation_id", "run_id", "flow_id", "endpoint_event_id", "first_us", "computer",
                        "client_process", "client_path", "server_process", "server_path", "server", "protocol",
                        "transport", "evidence_source", "policy", "status", "issues"]);
                    using (var command = Command(""))
                    {
                        var where = ObservationSql.Where(source, query, command);
                        command.CommandText = $"""
                            SELECT c.run_id,c.flow_id,c.first_us,c.source_process,c.source_path,c.destination_process,
                                c.destination_path,c.sni,c.destination_address,c.tls_version,c.group_name,
                                c.key_exchange,c.authentication,s.computer_name,c.id AS policy_observation_id,
                                c.ech_offered AS policy_ech_offered,c.tls_name AS policy_protocol,
                                {PolicyEvaluator.CertificateFactsSql(source)} AS policy_certificate_facts,
                                c.crypto_json AS metadata_json
                            FROM {source.Prefix}connections c JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id
                            WHERE {where} ORDER BY c.first_us,c.id
                            """;
                        using var registration = cancellation.Register(command.Cancel);
                        using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
                        while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
                            Assessment(PolicyEvaluator.ConnectionEvidence(reader, reader["computer_name"].ToString()!));
                    }
                    using (var command = Command(""))
                    {
                        var where = InvestigationSql.EndpointWhere(source, query, command, operationTime: true);
                        var endpointJson = source.SafeJson("e.detail_json");
                        var assessment = source.Provider == DatabaseProvider.SqlServer ?
                            $"JSON_QUERY({endpointJson},'$.assessment')" : source.JsonValue(endpointJson, "assessment");
                        command.CommandText = $"""
                            SELECT e.*,s.computer_name FROM {source.Prefix}endpoint_events e
                            JOIN {source.Prefix}capture_sessions s ON s.id=e.run_id
                            WHERE {where} AND {assessment} IS NOT NULL AND NOT EXISTS
                                (SELECT 1 FROM {source.Prefix}connections c
                                    WHERE {PolicyEvaluator.EndpointMatchSql(source, "e.detail_json", "c")})
                            ORDER BY e.timestamp_us,e.id
                            """;
                        using var registration = cancellation.Register(command.Cancel);
                        using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
                        while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
                            if (PolicyEvaluator.EndpointEvidence(reader["detail_json"].ToString()!,
                                reader["computer_name"].ToString()!, reader["id"].ToString()!,
                                reader["run_id"].ToString()!, Convert.ToInt64(reader["timestamp_us"]),
                                reader["protocol"].ToString()!) is { } evidence)
                                Assessment(evidence);
                    }
                }
                cancellation.ThrowIfCancellationRequested();
                writer.Flush();
                transaction.CommitAsync(cancellation).GetAwaiter().GetResult();
            }
            // Recheck a destination that may have been replaced while the report was being staged.
            cancellation.ThrowIfCancellationRequested();
            CheckTarget();
            cancellation.ThrowIfCancellationRequested();
            File.Move(temporary, target, overwrite: true);
            progress?.Report(count);
            return count;
        }
        catch (DbException error) when (cancellation.IsCancellationRequested)
        {
            throw new OperationCanceledException("Export cancelled.", error, cancellation);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static string Text(object value) => value is IFormattable number ?
        number.ToString(null, CultureInfo.InvariantCulture) :
        value is string text ? text : JsonSerializer.Serialize(value);

    private static string Quote(string value, bool protectFormula = false)
    {
        if (protectFormula && value.TrimStart() is { Length: > 0 } trimmed && trimmed[0] is '=' or '+' or '-' or '@' ||
            protectFormula && value.Length > 0 && value[0] is '\t' or '\r' or '\n')
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
