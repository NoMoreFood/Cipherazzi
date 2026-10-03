using System.Data.Common;
using System.Globalization;
using System.Text.Json;
using System.Xml.Linq;

namespace Cipherazzi.Data;

public sealed record AggregateRow(string Name, long Count, double? MeanHelloMs, double? MaximumHelloMs);
public sealed record TimelinePoint(long TimestampUs, long Count);
public sealed record AnalyticsSnapshot(long Total, long Selected, long Alerts, double? MeanHelloMs,
    List<AggregateRow> Protocols, List<AggregateRow> Groups, List<AggregateRow> Breakdown,
    List<TimelinePoint> Timeline, long FromUs, long ToUs, string Dimension);
public sealed record EndpointRow(string Id, long TimestampUs, string Provider, string Kind, string Result,
    string Pid, string Peer, string Protocol, string Cipher,
    string CertificateId, List<ObservationProperty> Properties);

public sealed record EndpointPage(List<EndpointRow> Rows, bool HasMore);

public static class Insights
{
    public static readonly IReadOnlyDictionary<string, string> Dimensions = new Dictionary<string, string>
    {
        ["Transport"] = "json:transport",
        ["Endpoint confirmation"] = "json:handshake_confirmation",
        ["Group classification"] = "json:group_class",
        ["Cipher suite"] = "cipher_name",
        ["Key-exchange group"] = "group_name",
        ["Key exchange"] = "key_exchange",
        ["Protocol"] = "tls_name",
        ["Server name"] = "sni",
        ["Client process"] = "source_process",
        ["Server process"] = "destination_process",
        ["Collector computer"] = "computer_name",
        ["Client owner"] = "CASE WHEN source_account='' THEN '' ELSE " +
            "CONCAT(source_account_domain,'\\',source_account) END",
        ["Server owner"] = "CASE WHEN destination_account='' THEN '' ELSE " +
            "CONCAT(destination_account_domain,'\\',destination_account) END",
        ["Authentication"] = "authentication",
        ["PSK selection"] = "psk_mode",
        ["Encryption"] = "encryption",
        ["Plaintext alert"] = "alert",
        ["Certificate fingerprint"] = "certificate_sha256",
        ["Observation state"] = "state"
    };

    public static AnalyticsSnapshot ReadAnalytics(DatabaseSource source, Query query, long sinceUs,
        string dimension, int top, CancellationToken cancellation)
    {
        if (!Dimensions.TryGetValue(dimension, out var field) || top is < 5 or > 100)
            throw new ArgumentException("Choose a supported analytics dimension.");
        var jsonDimension = field.StartsWith("json:", StringComparison.Ordinal);
        if (jsonDimension)
        {
            var key = field[5..];
            field = source.JsonText(key);
            if (key == "transport")
                field = $"COALESCE({field},'TCP')";
            if (source.Provider == DatabaseProvider.Sqlite)
                field = $"CASE WHEN json_valid(c.crypto_json) THEN {field} END";
        }
        if (dimension == "Server name")
        {
            var host = source.JsonText("http_host");
            if (source.Provider == DatabaseProvider.Sqlite)
                host = $"CASE WHEN json_valid(c.crypto_json) THEN {host} END";
            field = $"COALESCE(NULLIF(sni,''),{host},'')";
        }
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var transaction = source.BeginRead(connection, cancellation);
        var count = source.Provider == DatabaseProvider.SqlServer ? "COUNT_BIG(*)" : "COUNT(*)";
        using var filters = connection.CreateCommand();
        var where = ObservationSql.Where(source, query, filters, sinceUs);
        var table = $"{source.Prefix}connections c JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id";
        DbCommand Command(string sql)
        {
            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 2 : 10;
            command.CommandText = sql;
            foreach (DbParameter parameter in filters.Parameters)
                DatabaseSource.AddParameter(command, parameter.ParameterName, parameter.Value!);
            return command;
        }
        var materialize = source.Provider == DatabaseProvider.Sqlite ||
            source.Provider == DatabaseProvider.SqlServer && jsonDimension;
        if (materialize)
        {
            // Reuse one narrow scope so every chart does not scan and decode the full journal independently.
            var scopeTable = source.Provider == DatabaseProvider.SqlServer ? "#analysis_scope" : "temp.analysis_scope";
            var columns = $"first_us,tls_version,tls_name,group_name,alert,hello_latency_us,{field} AS dimension";
            if (source.Provider == DatabaseProvider.SqlServer)
            {
                // Keep the temporary table in session scope rather than a parameterized command's inner batch.
                using var schema = Command($"SELECT TOP (0) {columns} INTO {scopeTable} FROM {table}");
                schema.Parameters.Clear();
                using var registration = cancellation.Register(schema.Cancel);
                schema.ExecuteNonQueryAsync(cancellation).GetAwaiter().GetResult();
            }
            using var scope = Command(source.Provider == DatabaseProvider.SqlServer ?
                $"INSERT INTO {scopeTable} SELECT {columns} FROM {table} WHERE {where}" :
                $"CREATE TEMP TABLE analysis_scope AS SELECT {columns} FROM {table} WHERE {where}");
            using (var registration = cancellation.Register(scope.Cancel))
                scope.ExecuteNonQueryAsync(cancellation).GetAwaiter().GetResult();
            table = scopeTable;
            where = "1=1";
            field = "dimension";
            filters.Parameters.Clear();
        }
        using var summary = Command($"""
            SELECT {count},COALESCE(SUM(CASE WHEN tls_version IS NOT NULL THEN CAST(1 AS BIGINT) ELSE 0 END),0),
                COALESCE(SUM(CASE WHEN alert<>'' THEN CAST(1 AS BIGINT) ELSE 0 END),0),
                AVG(CAST(hello_latency_us AS FLOAT)),MIN(first_us),MAX(first_us)
            FROM {table} WHERE {where}
            """);
        long total, selected, alerts, first, last;
        double? mean;
        using (var registration = cancellation.Register(summary.Cancel))
        using (var reader = summary.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            reader.ReadAsync(cancellation).GetAwaiter().GetResult();
            total = Convert.ToInt64(reader[0]);
            selected = Convert.ToInt64(reader[1]);
            alerts = Convert.ToInt64(reader[2]);
            mean = reader.IsDBNull(3) ? null : Convert.ToDouble(reader[3]) / 1000;
            first = reader.IsDBNull(4) ? sinceUs : Convert.ToInt64(reader[4]);
            last = reader.IsDBNull(5) ? first : Convert.ToInt64(reader[5]);
        }

        // Bound timeline arithmetic and rendering to supported observation dates.
        _ = DateTimeOffset.FromUnixTimeMilliseconds(first / 1000);
        _ = DateTimeOffset.FromUnixTimeMilliseconds(last / 1000);
        List<AggregateRow> Group(string column)
        {
            using var command = Command($"""
                SELECT {(source.Provider == DatabaseProvider.SqlServer ? $"TOP ({top}) " : "")}
                    COALESCE(NULLIF({column},''),'Not observed') AS label,{count} AS total,
                    AVG(CAST(hello_latency_us AS FLOAT)),MAX(hello_latency_us)
                FROM {table} WHERE {where}
                GROUP BY COALESCE(NULLIF({column},''),'Not observed')
                ORDER BY total DESC,label {(source.Provider == DatabaseProvider.SqlServer ? "" : $"LIMIT {top}")}
                """);
            using var registration = cancellation.Register(command.Cancel);
            using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
            var result = new List<AggregateRow>();
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                cancellation.ThrowIfCancellationRequested();
                result.Add(new(reader.GetString(0), Convert.ToInt64(reader[1]),
                    reader.IsDBNull(2) ? null : Convert.ToDouble(reader[2]) / 1000,
                    reader.IsDBNull(3) ? null : Convert.ToDouble(reader[3]) / 1000));
            }
            return result;
        }
        var protocols = Group("tls_name");
        var groups = Group("group_name");
        var breakdown = Group(field);
        var bucket = Math.Max(1000000L, (last - first) / 60 + 1);
        using var timelineCommand = Command($"""
            SELECT (first_us/@bucket)*@bucket AS bucket,{count}
            FROM {table} WHERE {where} GROUP BY (first_us/@bucket)*@bucket ORDER BY bucket
            """);
        DatabaseSource.AddParameter(timelineCommand, "@bucket", bucket);
        var timeline = new List<TimelinePoint>();
        using (var registration = cancellation.Register(timelineCommand.Cancel))
        using (var reader = timelineCommand.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                cancellation.ThrowIfCancellationRequested();
                timeline.Add(new(Convert.ToInt64(reader[0]), Convert.ToInt64(reader[1])));
            }
        }
        if (materialize && source.Provider == DatabaseProvider.SqlServer)
        {
            using var cleanup = Command("DROP TABLE #analysis_scope");
            using var registration = cancellation.Register(cleanup.Cancel);
            cleanup.ExecuteNonQueryAsync(cancellation).GetAwaiter().GetResult();
        }
        transaction.CommitAsync(cancellation).GetAwaiter().GetResult();
        if (timeline.Count > 1)
        {
            var counts = timeline.ToDictionary(point => point.TimestampUs, point => point.Count);
            var end = timeline[^1].TimestampUs;
            var start = timeline[0].TimestampUs;
            timeline.Clear();
            for (var timestamp = start; timestamp <= end; timestamp += bucket)
            {
                cancellation.ThrowIfCancellationRequested();
                timeline.Add(new(timestamp, counts.GetValueOrDefault(timestamp)));
            }
        }
        return new(total, selected, alerts, mean, protocols, groups, breakdown, timeline, first, last, dimension);
    }

    public static List<ObservationProperty> ReadCertificates(DatabaseSource source, string[] references,
        CancellationToken cancellation)
    {
        var result = new List<ObservationProperty>();
        if (references.Length == 0)
            return result;
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        var selected = references.Take(64).Select(reference => reference.Split('|', 2))
            .Where(parts => parts.Length == 2).ToArray();
        if (selected.Length == 0)
            return result;

        // Fetch each certificate once, then preserve reference order and each presentation role.
        using var command = connection.CreateCommand();
        command.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 2 : 5;
        var hashes = selected.Select(parts => parts[1]).Distinct(StringComparer.Ordinal).ToArray();
        var parameters = hashes.Select((hash, index) => "@hash" + index).ToArray();
        for (var index = 0; index < hashes.Length; ++index)
            DatabaseSource.AddParameter(command, parameters[index], hashes[index]);
        command.CommandText = "WITH requested(sha256) AS (" +
            string.Join(" UNION ALL ", parameters.Select(parameter => "SELECT " + parameter)) + ") " +
            $"SELECT r.sha256,p.metadata_json FROM requested r JOIN {source.Prefix}certificates p ON p.sha256=r.sha256";
        using var registration = cancellation.Register(command.Cancel);
        var certificates = new Dictionary<string, List<ObservationProperty>>(StringComparer.Ordinal);
        using (var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                cancellation.ThrowIfCancellationRequested();
                var parsed = CertificateInventory.Metadata(reader.GetString(1));
                using var document = parsed ?? JsonDocument.Parse("{}");
                var fields = CertificateInventory.MetadataFields(document.RootElement, out var unreadable);
                var properties = CertificateInventory.MetadataProperties(fields, reader.GetString(0), "",
                    localTime: false, unreadable: unreadable);
                if (parsed is null)
                    properties.Add(new("", "Metadata", "Recorded certificate metadata could not be read"));
                certificates.Add(reader.GetString(0), properties);
            }
        }
        foreach (var parts in selected)
            if (certificates.TryGetValue(parts[1], out var properties))
                result.AddRange(properties.Select(property => property with { Category = parts[0] + " certificate" }));
        return result;
    }

    public static EndpointPage ReadEvents(DatabaseSource source, string search, long beforeUs,
        string beforeId, long sinceUs, CancellationToken cancellation)
        => ReadEvents(source, new Query(search, "", false,
            PageCursor.Newest), beforeUs, beforeId, sinceUs, cancellation);

    public static EndpointPage ReadEvents(DatabaseSource source, Query query, long beforeUs,
        string beforeId, long sinceUs, CancellationToken cancellation)
    {
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var command = connection.CreateCommand();
        command.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 2 : 5;
        var cursor = source.Provider == DatabaseProvider.SqlServer ?
            "timestamp_us<=@before AND (timestamp_us<@before OR e.id<@id)" :
            "(timestamp_us,e.id)<(@before,@id)";
        var where = InvestigationSql.EndpointWhere(source, query, command, sinceUs);
        var size = query.PageSize + 1;
        command.CommandText = $"""
            SELECT {(source.Provider == DatabaseProvider.SqlServer ? $"TOP ({size}) " : "")}e.*,s.computer_name
            FROM {source.Prefix}endpoint_events e JOIN {source.Prefix}capture_sessions s ON s.id=e.run_id
            WHERE {where} AND {cursor}
            ORDER BY timestamp_us DESC,e.id DESC
            {(source.Provider == DatabaseProvider.SqlServer ? "" : $"LIMIT {size}")}
            """;
        DatabaseSource.AddParameter(command, "@before", beforeUs);
        DatabaseSource.AddParameter(command, "@id", beforeId);
        using var registration = cancellation.Register(command.Cancel);
        using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
        var results = new List<EndpointRow>();
        while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
        {
            cancellation.ThrowIfCancellationRequested();
            string Text(string name) => reader[name].ToString()!;
            var properties = new List<ObservationProperty>();
            properties.Add(new("Endpoint evidence", "Collector computer", Text("computer_name"),
                "Computer running the collector or importing this telemetry."));
            foreach (var name in new[] { "provider", "kind", "result", "pid", "peer", "port", "protocol",
                "cipher", "certificate_id", "run_id", "id" })
                properties.Add(new("Endpoint evidence", Label(name), Text(name)));

            // Keep recorded event fields available when provider metadata cannot be decoded.
            try
            {
                var json = Text("detail_json");
                if (json.Length > 2 * 1024 * 1024)
                    throw new JsonException("Endpoint evidence exceeds the inspection bound.");
                using var document = JsonDocument.Parse(json);
                foreach (var item in document.RootElement.EnumerateObject())
                {
                    if (item.Name == "xml" && item.Value.GetString() is { Length: > 0 } xml)
                    {
                        try
                        {
                            var parsed = XDocument.Parse(xml);
                            foreach (var element in parsed.Descendants().Where(node =>
                                !node.HasElements && node.Name.LocalName is not "System" && node.Value.Length > 0))
                            {
                                if (properties.Count >= 256)
                                    break;
                                properties.Add(new("Windows event", element.Attribute("Name")?.Value ??
                                    element.Name.LocalName, element.Value));
                            }
                        }
                        catch (System.Xml.XmlException) { }
                    }
                    else
                        properties.Add(new("Provider metadata", Label(item.Name), item.Value.ToString()));
                }
            }
            catch (Exception error) when (error is JsonException or InvalidOperationException)
            {
                properties.Insert(1, new("Endpoint evidence", "Provider metadata",
                    "Recorded endpoint metadata could not be read"));
            }
            results.Add(new(Text("id"), Convert.ToInt64(reader["timestamp_us"]), Text("provider"), Text("kind"),
                Text("result"), Text("pid"), Text("peer"), Text("protocol"), Text("cipher"),
                Text("certificate_id"), properties));
        }
        var more = results.Count > query.PageSize;
        if (more)
            results.RemoveAt(query.PageSize);
        return new(results, more);
    }

    internal static string Label(string value) => value switch
    {
        "not_after_us" => "Expires",
        "not_before_us" => "Valid from",
        "first_us" => "First observed",
        "last_us" => "Last observed",
        _ => string.Join(' ', value.Split('_').Select(word => word switch
        {
            "pid" => "PID",
            "id" => "ID",
            "alpn" => "ALPN",
            "sni" => "SNI",
            "tls" => "TLS",
            "ssl" => "SSL",
            "quic" => "QUIC",
            "der" => "DER",
            "dns" => "DNS",
            "oid" => "OID",
            "spki" => "SPKI",
            "sha256" => "SHA-256",
            "vpn" => "VPN",
            "ike" => "IKE",
            "ikev1" => "IKEv1",
            "wireguard" => "WireGuard",
            "openvpn" => "OpenVPN",
            "ssl2" => "SSL 2.0",
            "ssh" => "SSH",
            "smb" => "SMB",
            "rdp" => "RDP",
            "tds" => "TDS",
            "ca" => "CA",
            "krb" => "Kerberos",
            "ntlm" => "NTLM",
            "spnego" => "SPNEGO",
            "iwarp" => "iWARP",
            "rdma" => "RDMA",
            "roce" => "RoCE",
            "udp" => "UDP",
            "crc" => "CRC",
            "ldap" => "LDAP",
            "sasl" => "SASL",
            "sspi" => "SSPI",
            "starttls" => "StartTLS",
            "negoex" => "NegoEx",
            "iakerb" => "IAKerb",
            "http" => "HTTP",
            "rpc" => "RPC",
            "smtp" => "SMTP",
            "imap" => "IMAP",
            "pop3" => "POP3",
            "ftp" => "FTP",
            "postgresql" => "PostgreSQL",
            "mysql" => "MySQL",
            "ipsec" => "IPsec",
            "spi" => "SPI",
            "esp" => "ESP",
            "ah" => "AH",
            "gss" => "GSS",
            _ => CultureInfo.CurrentCulture.TextInfo.ToTitleCase(word)
        }))
    };
}
