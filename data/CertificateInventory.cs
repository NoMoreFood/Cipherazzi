using System.Data.Common;
using System.Security.Cryptography;
using System.Text.Json;

namespace Cipherazzi.Data;

public sealed record CertificateRow(string Sha256, string Subject, string Issuer, string PublicKey,
    string KeyClass, string Signature, string SignatureClass, string SpkiSha256, long? NotBeforeUs, long? NotAfterUs,
    long? FirstUs, long? LastUs, long Observations, long Computers, long Applications, long KeyReuse,
    List<ObservationProperty> Properties);
public sealed record CertificatePage(List<CertificateRow> Rows, bool HasMore);
public sealed record CertificateUse(string Computer, string ClientApplication, string ServerApplication, string Peer,
    string Role, long ChainIndex, long Observations, long FirstUs, long LastUs);

public static class CertificateInventory
{
    public static readonly string[] Filters = ["All certificates", "Expires within 30 days", "Expired",
        "PQ public key", "Classical public key", "Reused public key"];

    public static CertificatePage Read(DatabaseSource source, string search, string filter, string after,
        CancellationToken cancellation, int pageSize = 250)
    {
        if (!Filters.Contains(filter) || pageSize is < 50 or > 2000)
            throw new ArgumentException("Choose a supported certificate filter and page size.");
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var command = connection.CreateCommand();
        command.CommandTimeout = 30;
        var conditions = new List<string> { "p.sha256>@after" };
        DatabaseSource.AddParameter(command, "@after", after);
        var spki = source.JsonValue("p.metadata_json", "spki_sha256");
        var reuse = "COALESCE(k.total,0)";
        var expires = $"CAST({source.JsonValue("p.metadata_json", "not_after_us")} AS BIGINT)";
        if (filter is "Expired" or "Expires within 30 days")
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
            conditions.Add(expires + (filter == "Expired" ? "<@now" : ">=@now AND " + expires + "<=@expires"));
            DatabaseSource.AddParameter(command, "@now", now);
            if (filter != "Expired")
                DatabaseSource.AddParameter(command, "@expires", now + 30L * 24 * 60 * 60 * 1000000);
        }
        else if (filter is "PQ public key" or "Classical public key")
        {
            conditions.Add(source.JsonValue("p.metadata_json", "public_key_class") + "=@class");
            DatabaseSource.AddParameter(command, "@class", filter == "PQ public key" ? "Post-quantum" : "Classical");
        }
        else if (filter == "Reused public key")
            conditions.Add(reuse + ">1");
        if (search.Length > 0)
        {
            string Matches(string field) => source.TextMatch(field, "@pattern");
            conditions.Add($"""
                ({Matches("p.sha256")} OR {Matches("p.metadata_json")} OR EXISTS
                    (SELECT 1 FROM {source.Prefix}connection_certificates l
                    JOIN {source.Prefix}connections c ON c.run_id=l.run_id AND c.flow_id=l.flow_id
                    JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id WHERE l.sha256=p.sha256 AND
                    ({Matches("s.computer_name")} OR {Matches("c.source_process")}
                        OR {Matches("c.destination_process")} OR {Matches("c.source_path")}
                        OR {Matches("c.destination_path")} OR {Matches("c.sni")})))
                """);
            DatabaseSource.AddParameter(command, "@pattern", "%" + search.Replace("\\", "\\\\")
                .Replace("%", "\\%").Replace("_", "\\_").Replace("[", "\\[") + "%");
        }
        var where = string.Join(" AND ", conditions);
        var clientApplication = "COALESCE(NULLIF(c.source_path,''),NULLIF(c.source_process,''))";
        var serverApplication = "COALESCE(NULLIF(c.destination_path,''),NULLIF(c.destination_process,''))";
        command.CommandText = $"""
            WITH key_counts AS
            (SELECT {spki} AS spki,COUNT(*) AS total FROM {source.Prefix}certificates p
                WHERE {spki} IS NOT NULL AND {spki}<>'' GROUP BY {spki}),
            candidates AS
            (SELECT {(source.Provider == DatabaseProvider.SqlServer ? $"TOP ({pageSize + 1}) " : "")}
                p.sha256,p.metadata_json,{reuse} AS key_reuse FROM {source.Prefix}certificates p
                    LEFT JOIN key_counts k ON k.spki={spki}
                WHERE {where} ORDER BY p.sha256 {(source.Provider == DatabaseProvider.SqlServer ? "" : $"LIMIT {pageSize + 1}")}),
            uses AS
            (SELECT DISTINCT l.sha256,c.run_id,c.flow_id,c.first_us,c.last_us,s.computer_name,
                {clientApplication} AS client_application,{serverApplication} AS server_application
                FROM {source.Prefix}connection_certificates l JOIN candidates p ON p.sha256=l.sha256
                JOIN {source.Prefix}connections c ON c.run_id=l.run_id AND c.flow_id=l.flow_id
                JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id),
            usage AS
            (SELECT sha256,COUNT(*) AS observations,COUNT(DISTINCT computer_name) AS computers,
                MIN(first_us) AS first_us,MAX(last_us) AS last_us
                FROM uses GROUP BY sha256)
            ,applications AS
            (SELECT sha256,COUNT(DISTINCT application) AS total FROM
                (SELECT sha256,client_application AS application FROM uses
                    UNION ALL SELECT sha256,server_application AS application FROM uses) names GROUP BY sha256)
            SELECT p.sha256,p.metadata_json,p.key_reuse,u.observations,u.computers,a.total,u.first_us,u.last_us
                FROM candidates p LEFT JOIN usage u ON u.sha256=p.sha256
                LEFT JOIN applications a ON a.sha256=p.sha256 ORDER BY p.sha256
            """;
        var rows = new List<CertificateRow>();
        using var registration = cancellation.Register(command.Cancel);
        using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
        while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
        {
            cancellation.ThrowIfCancellationRequested();
            using var document = JsonDocument.Parse(reader.GetString(1));
            var metadata = document.RootElement;
            string Text(string name) => metadata.TryGetProperty(name, out var value) ? value.ToString() : "";
            long? Number(string name) => metadata.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number &&
                value.TryGetInt64(out var number) ? number : null;
            long Count(int ordinal) => reader.IsDBNull(ordinal) ? 0 : Convert.ToInt64(reader[ordinal]);
            long? Time(int ordinal) => reader.IsDBNull(ordinal) ? null : Convert.ToInt64(reader[ordinal]);
            var properties = metadata.EnumerateObject().Select(property => new ObservationProperty("Certificate",
                Insights.Label(property.Name), property.Name.EndsWith("_us") && Number(property.Name) is { } time ?
                    At(time) : property.Value.ValueKind == JsonValueKind.Array ?
                    string.Join(", ", property.Value.EnumerateArray().Select(value => value.ToString())) : property.Value.ToString(),
                "Observed public certificate metadata. Endpoint trust outcomes are recorded separately.")).ToList();
            var row = new CertificateRow(reader.GetString(0), Text("subject"), Text("issuer"), Text("public_key_type"),
                Text("public_key_class"), Text("signature_algorithm"), Text("certificate_signature_class"),
                Text("spki_sha256"), Number("not_before_us"), Number("not_after_us"), Time(6), Time(7), Count(3),
                Count(4), Count(5), Count(2), properties);
            properties.AddRange(new[]
            {
                new ObservationProperty("Inventory", "Linked observations", row.Observations.ToString("N0")),
                new ObservationProperty("Inventory", "Collector computers", row.Computers.ToString("N0")),
                new ObservationProperty("Inventory", "Local applications", row.Applications.ToString("N0")),
                new ObservationProperty("Inventory", "Certificates sharing SPKI", row.KeyReuse.ToString("N0")),
                new ObservationProperty("Inventory", "First observed", At(row.FirstUs)),
                new ObservationProperty("Inventory", "Last observed", At(row.LastUs))
            });
            rows.Add(row);
        }
        var more = rows.Count > pageSize;
        if (more)
            rows.RemoveAt(pageSize);
        return new(rows, more);
    }

    public static List<CertificateUse> ReadUses(DatabaseSource source, string sha256, CancellationToken cancellation)
    {
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var command = connection.CreateCommand();
        command.CommandTimeout = 30;
        command.CommandText = $"""
            SELECT {(source.Provider == DatabaseProvider.SqlServer ? "TOP (250) " : "")}
                s.computer_name,COALESCE(NULLIF(c.source_path,''),c.source_process),
                COALESCE(NULLIF(c.destination_path,''),c.destination_process),
                COALESCE(NULLIF(c.sni,''),c.destination_address),l.role,l.chain_index,
                COUNT(*),MIN(c.first_us),MAX(c.last_us)
            FROM {source.Prefix}connection_certificates l
                JOIN {source.Prefix}connections c ON c.run_id=l.run_id AND c.flow_id=l.flow_id
                JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id WHERE l.sha256=@hash
            GROUP BY s.computer_name,COALESCE(NULLIF(c.source_path,''),c.source_process),
                COALESCE(NULLIF(c.destination_path,''),c.destination_process),
                COALESCE(NULLIF(c.sni,''),c.destination_address),l.role,l.chain_index
            ORDER BY MAX(c.last_us) DESC {(source.Provider == DatabaseProvider.SqlServer ? "" : "LIMIT 250")}
            """;
        DatabaseSource.AddParameter(command, "@hash", sha256);
        using var registration = cancellation.Register(command.Cancel);
        using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
        var uses = new List<CertificateUse>();
        while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            uses.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), Convert.ToInt64(reader[5]), Convert.ToInt64(reader[6]),
                Convert.ToInt64(reader[7]), Convert.ToInt64(reader[8])));
        return uses;
    }

    public static byte[] ReadDer(DatabaseSource source, string sha256, CancellationToken cancellation)
    {
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var command = connection.CreateCommand();
        command.CommandTimeout = 10;
        var length = source.Provider switch
        {
            DatabaseProvider.SqlServer => "DATALENGTH(der)", DatabaseProvider.PostgreSql => "OCTET_LENGTH(der)", _ => "LENGTH(der)"
        };
        command.CommandText = $"SELECT der FROM {source.Prefix}certificates WHERE sha256=@hash AND {length}<=1048576";
        DatabaseSource.AddParameter(command, "@hash", sha256);
        using var registration = cancellation.Register(command.Cancel);
        var der = command.ExecuteScalarAsync(cancellation).GetAwaiter().GetResult() as byte[];
        if (der is null || der.Length == 0 || !Convert.ToHexString(SHA256.HashData(der)).Equals(sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Certificate data is unavailable or does not match its SHA-256 fingerprint.");
        return der;
    }

    public static string At(long? time) => time is null ? "Not observed" :
        DateTimeOffset.FromUnixTimeMilliseconds(time.Value / 1000).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz");
}
