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
    string EndpointApplication, string Evidence, string Role, long ChainIndex, long Observations,
    long FirstUs, long LastUs);

public static class CertificateInventory
{
    internal const long MinimumTimeUs = -62135596800000000;
    internal const long MaximumTimeUs = 253402300799999999;
    private const int MaximumMetadataValue = 16384;
    private static readonly string[] MetadataDisplayFields = ["subject", "issuer", "public_key_type",
        "public_key_bits", "public_key_class", "public_key_oid", "signature_algorithm", "signature_oid",
        "certificate_signature_class", "not_before_us", "not_after_us", "serial", "spki_sha256", "trust",
        "decode_status", "dns_names"];
    internal readonly record struct MetadataValue(JsonElement Value, bool Unique);
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
        var spki = source.JsonScalar("p.metadata_json", "spki_sha256");
        var reuse = "COALESCE(k.total,0)";
        if (filter is "Expired" or "Expires within 30 days")
        {
            var begins = source.JsonScalar("p.metadata_json", "not_before_us", integer: true,
                minimum: MinimumTimeUs, maximum: MaximumTimeUs);
            var ends = source.JsonScalar("p.metadata_json", "not_after_us", integer: true,
                minimum: MinimumTimeUs, maximum: MaximumTimeUs);
            var expires = $"CASE WHEN {begins}<={ends} OR {begins} IS NULL THEN {ends} END";
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
            conditions.Add(expires + (filter == "Expired" ? "<@now" : ">=@now AND " + expires + "<=@expires"));
            DatabaseSource.AddParameter(command, "@now", now);
            if (filter != "Expired")
                DatabaseSource.AddParameter(command, "@expires", now + 30L * 24 * 60 * 60 * 1000000);
        }
        else if (filter is "PQ public key" or "Classical public key")
        {
            conditions.Add(source.JsonScalar("p.metadata_json", "public_key_class") + "=@class");
            DatabaseSource.AddParameter(command, "@class", filter == "PQ public key" ? "Post-quantum" : "Classical");
        }
        else if (filter == "Reused public key")
            conditions.Add(reuse + ">1");
        if (search.Length > 0)
        {
            string Matches(string field) => source.TextMatch(command, field, "@pattern", search);
            conditions.Add($"""
                ({Matches("p.sha256")} OR {Matches("p.metadata_json")} OR EXISTS
                    (SELECT 1 FROM certificate_uses u WHERE u.sha256=p.sha256 AND
                    ({Matches("u.computer_name")} OR {Matches("u.client_application")}
                        OR {Matches("u.server_application")} OR {Matches("u.endpoint_application")}
                        OR {Matches("u.peer")})))
                """);
            DatabaseSource.AddParameter(command, "@pattern", "%" + InvestigationSql.Escape(search) + "%");
        }
        var where = string.Join(" AND ", conditions);
        command.CommandText = $"""
            WITH certificate_uses AS ({UsageSql(source)}),
            catalog AS (SELECT p.sha256,p.metadata_json,{spki} AS spki FROM {source.Prefix}certificates p),
            key_counts AS
            (SELECT spki,COUNT(*) AS total FROM catalog WHERE spki IS NOT NULL AND spki<>'' GROUP BY spki),
            candidates AS
            (SELECT {(source.Provider == DatabaseProvider.SqlServer ? $"TOP ({pageSize + 1}) " : "")}
                p.sha256,p.metadata_json,{reuse} AS key_reuse FROM catalog p
                    LEFT JOIN key_counts k ON k.spki=p.spki
                WHERE {where} ORDER BY p.sha256 {(source.Provider == DatabaseProvider.SqlServer ?
                    "" : $"LIMIT {pageSize + 1}")}),
            uses AS
            (SELECT u.* FROM certificate_uses u JOIN candidates p ON p.sha256=u.sha256),
            observations AS
            (SELECT sha256,run_id,flow_id,event_id,computer_name,MIN(first_us) AS first_us,MAX(last_us) AS last_us
                FROM uses GROUP BY sha256,run_id,flow_id,event_id,computer_name),
            usage AS
            (SELECT sha256,COUNT(*) AS observations,COUNT(DISTINCT computer_name) AS computers,
                MIN(first_us) AS first_us,MAX(last_us) AS last_us FROM observations GROUP BY sha256),
            applications AS
            (SELECT sha256,COUNT(DISTINCT NULLIF(application,'')) AS total FROM
                (SELECT sha256,client_application AS application FROM uses
                    UNION ALL SELECT sha256,server_application AS application FROM uses
                    UNION ALL SELECT sha256,endpoint_application AS application FROM uses) names GROUP BY sha256)
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
            // Retain the fingerprint and usage when catalog metadata cannot be decoded.
            var parsed = Metadata(reader.GetString(1));
            using var document = parsed ?? JsonDocument.Parse("{}");
            var fields = MetadataFields(document.RootElement, out var unreadable);
            var properties = MetadataProperties(fields, reader.GetString(0), "Certificate", localTime: true,
                unreadable: unreadable);
            if (parsed is null)
                properties.Add(new("Certificate", "Metadata", "Recorded certificate metadata could not be read"));
            string Text(string name) => MetadataText(fields, name);
            long Count(int ordinal) => reader.IsDBNull(ordinal) ? 0 : Convert.ToInt64(reader[ordinal]);
            long? Time(int ordinal) => reader.IsDBNull(ordinal) ? null : Convert.ToInt64(reader[ordinal]);

            // Invalid or contradictory dates cannot place a certificate into an expiry cohort.
            var notBefore = MetadataTime(fields, "not_before_us");
            var notAfter = MetadataTime(fields, "not_after_us");
            var reversed = notBefore > notAfter;
            var row = new CertificateRow(reader.GetString(0), Text("subject"), Text("issuer"), Text("public_key_type"),
                Text("public_key_class"), Text("signature_algorithm"), Text("certificate_signature_class"),
                Text("spki_sha256"), reversed ? null : notBefore, reversed ? null : notAfter,
                Time(6), Time(7), Count(3), Count(4), Count(5), Count(2), properties);
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
            WITH certificate_uses AS ({UsageSql(source)}),
            uses AS
            (SELECT DISTINCT run_id,flow_id,event_id,computer_name,client_application,server_application,
                endpoint_application,peer,evidence,role,chain_index,first_us,last_us
                FROM certificate_uses WHERE sha256=@hash)
            SELECT {(source.Provider == DatabaseProvider.SqlServer ? "TOP (250) " : "")}
                computer_name,client_application,server_application,peer,endpoint_application,evidence,role,
                chain_index,COUNT(*),MIN(first_us),MAX(last_us) FROM uses
            GROUP BY computer_name,client_application,server_application,peer,endpoint_application,evidence,role,
                chain_index
            ORDER BY MAX(last_us) DESC {(source.Provider == DatabaseProvider.SqlServer ? "" : "LIMIT 250")}
            """;
        DatabaseSource.AddParameter(command, "@hash", sha256);
        using var registration = cancellation.Register(command.Cancel);
        using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
        var uses = new List<CertificateUse>();
        while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            uses.Add(new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), reader.GetString(5), reader.GetString(6), Convert.ToInt64(reader[7]),
                Convert.ToInt64(reader[8]), Convert.ToInt64(reader[9]), Convert.ToInt64(reader[10])));
        return uses;
    }

    private static string UsageSql(DatabaseSource source)
    {
        // A matched endpoint report shares its negotiation identity, while unmatched reports remain independent.
        string Field(string name) => source.JsonValue(source.SafeJson("e.detail_json"), name);
        string Time(string name) => source.JsonScalar("e.detail_json", "assessment." + name,
            integer: true, minimum: 0, maximum: 253402300799999999);
        var application = $"COALESCE(NULLIF({Field("assessment.path")},''),{Field("assessment.process")},'')";
        var role = Field("assessment.local_role");

        // Inconsistent reported bounds cannot define an observation interval, including partial timestamps.
        const string first = "COALESCE(e.reported_first_us,e.timestamp_us)";
        const string last = "COALESCE(e.reported_last_us,e.timestamp_us)";
        return $"""
            SELECT l.sha256,c.run_id,c.flow_id,'' AS event_id,c.first_us,c.last_us,s.computer_name,
                COALESCE(NULLIF(c.source_path,''),c.source_process,'') AS client_application,
                COALESCE(NULLIF(c.destination_path,''),c.destination_process,'') AS server_application,
                '' AS endpoint_application,COALESCE(NULLIF(c.sni,''),c.destination_address,'') AS peer,
                'Packet' AS evidence,l.role,l.chain_index
            FROM {source.Prefix}connection_certificates l
                JOIN {source.Prefix}connections c ON c.run_id=l.run_id AND c.flow_id=l.flow_id
                JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id
            UNION ALL
            SELECT l.sha256,COALESCE(c.run_id,e.run_id),c.flow_id,
                CASE WHEN c.flow_id IS NULL THEN e.id ELSE '' END,
                COALESCE(c.first_us,CASE WHEN {first}<={last} THEN {first} ELSE e.timestamp_us END),
                COALESCE(c.last_us,CASE WHEN {first}<={last} THEN {last} ELSE e.timestamp_us END),s.computer_name,
                COALESCE(NULLIF(c.source_path,''),NULLIF(c.source_process,''),
                    CASE WHEN {role}='Client' THEN {application} ELSE '' END),
                COALESCE(NULLIF(c.destination_path,''),NULLIF(c.destination_process,''),
                    CASE WHEN {role}='Server' THEN {application} ELSE '' END),
                {application},COALESCE(NULLIF({Field("assessment.server_name")},''),e.peer,''),
                'Endpoint','Not reported',-1
            FROM {source.Prefix}endpoint_certificates l
                JOIN (SELECT e.*,{Time("first_us")} AS reported_first_us,
                    {Time("last_us")} AS reported_last_us FROM {source.Prefix}endpoint_events e) e ON e.id=l.event_id
                JOIN {source.Prefix}capture_sessions s ON s.id=e.run_id
                LEFT JOIN {source.Prefix}connections c
                    ON {PolicyEvaluator.EndpointMatchSql(source, "e.detail_json", "c")}
            """;
    }

    public static byte[] ReadDer(DatabaseSource source, string sha256, CancellationToken cancellation)
    {
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var command = connection.CreateCommand();
        command.CommandTimeout = 10;
        var length = source.Provider switch
        {
            DatabaseProvider.SqlServer => "DATALENGTH(der)",
            DatabaseProvider.PostgreSql => "OCTET_LENGTH(der)",
            _ => "LENGTH(der)"
        };
        command.CommandText = $"SELECT der FROM {source.Prefix}certificates WHERE sha256=@hash AND {length}<=1048576";
        DatabaseSource.AddParameter(command, "@hash", sha256);
        using var registration = cancellation.Register(command.Cancel);
        var der = command.ExecuteScalarAsync(cancellation).GetAwaiter().GetResult() as byte[];
        if (der is null || der.Length == 0 || !Convert.ToHexString(SHA256.HashData(der)).Equals(sha256,
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "Certificate data is unavailable or does not match its SHA-256 fingerprint.");
        return der;
    }

    internal static JsonDocument? Metadata(string json)
    {
        // Decode bounded catalog objects independently so one damaged certificate cannot hide its siblings.
        if (json.Length > 2 * 1024 * 1024)
            return null;
        try
        {
            var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
            if (document.RootElement.ValueKind == JsonValueKind.Object)
                return document;
            document.Dispose();
        }
        catch (JsonException) { }
        return null;
    }

    internal static Dictionary<string, MetadataValue> MetadataFields(JsonElement metadata, out bool unreadable)
    {
        // Index each field once; ambiguous names remain unavailable to typed readers.
        var fields = new Dictionary<string, MetadataValue>(StringComparer.Ordinal);
        unreadable = false;
        foreach (var property in metadata.EnumerateObject())
        {
            string name;
            try { name = property.Name; }
            catch (InvalidOperationException) { unreadable = true; continue; }
            fields[name] = new(property.Value, !fields.ContainsKey(name));
        }
        return fields;
    }

    private static string MetadataText(IReadOnlyDictionary<string, MetadataValue> fields, string name)
    {
        try
        {
            return fields.TryGetValue(name, out var field) && field.Unique &&
                field.Value.ValueKind == JsonValueKind.String ?
                ClipMetadata(field.Value.GetString()!, MaximumMetadataValue) : "";
        }
        catch (InvalidOperationException) { return ""; }
    }

    internal static long? MetadataTime(IReadOnlyDictionary<string, MetadataValue> fields, string name) =>
        fields.TryGetValue(name, out var field) && field.Unique && field.Value.ValueKind == JsonValueKind.Number &&
        field.Value.TryGetInt64(out var number) && number is >= MinimumTimeUs and <= MaximumTimeUs ? number : null;

    internal static List<ObservationProperty> MetadataProperties(IReadOnlyDictionary<string, MetadataValue> fields,
        string hash, string category, bool localTime, bool unreadable = false)
    {
        // Keep certificate identity and common fields ahead of extensions within a bounded inspector payload.
        var properties = new List<ObservationProperty> { new(category, "SHA-256", hash) };
        var names = MetadataDisplayFields.Where(fields.ContainsKey).Concat(fields.Keys.Where(name =>
            name != "sha256" && !MetadataDisplayFields.Contains(name, StringComparer.Ordinal))).Take(128).ToArray();
        var limited = fields.Keys.Count(name => name != "sha256") > names.Length;
        var remaining = 65536;
        foreach (var name in names)
        {
            var element = fields[name].Value;
            string value;
            try
            {
                if (name.EndsWith("_us") && MetadataTime(fields, name) is { } time)
                    value = localTime ? At(time) : DateTimeOffset.FromUnixTimeMilliseconds(time / 1000).ToString("u");
                else if (element.ValueKind == JsonValueKind.Array)
                {
                    value = string.Join(", ", element.EnumerateArray().Take(256).Select(item => item.ToString()));
                    limited |= element.GetArrayLength() > 256;
                }
                else
                    value = element.ToString();
            }
            catch (InvalidOperationException) { unreadable = true; continue; }
            var label = ClipMetadata(name, 256);
            var displayed = ClipMetadata(value, Math.Min(remaining, MaximumMetadataValue));
            limited |= label != name || displayed != value;
            properties.Add(new(category, Insights.Label(label), displayed,
                "Observed public certificate metadata. Endpoint trust outcomes are recorded separately."));
            remaining -= displayed.Length;
            if (remaining <= 0)
            {
                limited = true;
                break;
            }
        }
        if (unreadable)
            properties.Add(new(category, "Metadata", "Recorded certificate metadata could not be read"));
        if (limited)
            properties.Add(new(category, "Metadata", "Recorded certificate metadata exceeds the display limit"));
        if (fields.Values.Any(field => !field.Unique))
            properties.Add(new(category, "Metadata", "Recorded certificate metadata contains duplicate fields"));
        if (MetadataTime(fields, "not_before_us") > MetadataTime(fields, "not_after_us") ||
            new[] { "not_before_us", "not_after_us" }.Any(name => fields.TryGetValue(name, out var field) &&
                field.Value.ValueKind != JsonValueKind.Null && MetadataTime(fields, name) is null))
            properties.Add(new(category, "Metadata", "Recorded certificate validity dates are invalid"));
        return properties;
    }

    private static string ClipMetadata(string value, int maximum)
    {
        if (value.Length <= maximum)
            return value;
        var length = Math.Max(0, maximum - 1);
        if (length > 0 && char.IsHighSurrogate(value[length - 1]))
            --length;
        return value[..length] + "…";
    }

    public static string At(long? time) => time is null ? "Not observed" :
        time is < MinimumTimeUs or > MaximumTimeUs ? "Invalid timestamp" :
        DateTimeOffset.FromUnixTimeMilliseconds(time.Value / 1000).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz");
}
