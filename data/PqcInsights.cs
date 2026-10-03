using System.Data.Common;
using System.Text;
using System.Text.Json;

namespace Cipherazzi.Data;

public sealed record CertificateEvidence(string Role, string KeyOid, string SignatureOid,
    string KeyClass, string SignatureClass);

public sealed record FlowEvidence
{
    public long Id { get; init; }
    public string RunId { get; init; } = "";
    public long FlowId { get; init; }
    public long FirstUs { get; init; }
    public string Computer { get; init; } = "";
    public string ClientProcess { get; init; } = "";
    public string ClientPath { get; init; } = "";
    public string ServerProcess { get; init; } = "";
    public string ServerPath { get; init; } = "";
    public string ServerName { get; init; } = "";
    public string EndpointEventId { get; init; } = "";
    public string EndpointProcess { get; init; } = "";
    public string EndpointPath { get; init; } = "";
    public string EvidenceSource { get; private set; } = "Packet";
    public string Protocol { get; internal set; } = "TLS";
    public string EvidenceError { get; internal set; } = "";
    public string Transport { get; private set; } = "TCP";
    public int Tls { get; init; }
    public bool EchOffered { get; init; }
    public int GroupId { get; private set; } = -1;
    public string GroupName { get; init; } = "";
    public string GroupStatus { get; private set; } = "";
    public string KeyClass { get; private set; } = "Not observed";
    public string ServerAuth { get; private set; } = "Not observed";
    public string ClientAuth { get; private set; } = "Not observed";
    public string Completion { get; private set; } = "Not confirmed";
    public string PeerVerification { get; private set; } = "Not reported";
    public string RuleVersion { get; private set; } = "Not recorded";
    public string ChainSignatures { get; private set; } = "Not observed";
    public string CertificateKeys { get; private set; } = "Not observed";
    internal string[] CountKeys { get; private set; } = [];
    public HashSet<int> ServerSignatureIds { get; } = [];
    public HashSet<int> ClientSignatureIds { get; } = [];
    public List<CertificateEvidence> Certificates { get; } = [];
    public List<string> MissingEvidence { get; } = [];
    internal JsonElement ProtocolEvidence { get; private set; }

    internal FlowEvidence Decode(string json, string certificateFacts, string keyExchange, string authentication)
    {
        // Classification describes observed operations; completion and trust retain independent outcomes.
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 32 });
        var crypto = document.RootElement;
        bool Value(JsonElement element, string name, out JsonElement value)
        {
            if (element.ValueKind != JsonValueKind.Array)
                return element.TryGetProperty(name, out value);
            var fields = element.GetArrayLength() == PqcInsights.ProfileFields.Length ?
                PqcInsights.ProfileFields : PqcInsights.EndpointFields;
            var index = Array.IndexOf(fields, name);
            value = index >= 0 && index < element.GetArrayLength() ? element[index] : default;
            return index >= 0 && index < element.GetArrayLength();
        }
        string Text(JsonElement element, string name) => Value(element, name, out var value) ? value.ToString() : "";
        int Number(JsonElement element, string name) => Value(element, name, out var value) &&
            int.TryParse(value.ToString(), out var number) ? number : -1;
        Transport = Text(crypto, "transport") is { Length: > 0 } transport ? transport : "TCP";
        Protocol = Text(crypto, "protocol") is { Length: > 0 } protocol ? protocol : "TLS";
        if (Protocol is not ("TLS" or "DTLS"))
            ProtocolEvidence = crypto.Clone();
        EvidenceSource = Text(crypto, "evidence_source") is { Length: > 0 } evidenceSource ? evidenceSource : "Packet";
        GroupId = Number(crypto, "selected_group_id");
        GroupStatus = Text(crypto, "group_standardization");
        RuleVersion = Text(crypto, "classification_rule_version") is { Length: > 0 } version ? version : "Not recorded";
        KeyClass = Text(crypto, "group_class");
        if (KeyClass.Length == 0 || KeyClass == "Not observed")
            KeyClass = keyExchange == "RSA" || keyExchange.Contains("Diffie-Hellman", StringComparison.OrdinalIgnoreCase) ?
                "Classical" : keyExchange == "PSK only" ? "PSK only" : "Not observed";
        var serverClasses = new List<string>();
        var clientClasses = new List<string>();
        var completions = new List<bool>();
        var verifications = new List<int>();
        var reportedCertificates = new List<string>();
        if (Value(crypto, "endpoint_confirmations", out var confirmations) &&
            confirmations.ValueKind == JsonValueKind.Array)
        {
            foreach (var report in confirmations.EnumerateArray())
            {
                reportedCertificates.Add(Text(report, "certificate_facts"));
                var success = Text(report, "success") is "True" or "true" or "1";
                completions.Add(success);
                // A reported verification rejection remains evidence when the handshake cannot complete.
                var verification = Number(report, "peer_verified");
                if (success || verification == 0) verifications.Add(verification);
                if (!success)
                    continue;
                var client = Text(report, "local_role") == "Client";
                foreach (var (local, classes, ids) in new[]
                {
                    (!client, serverClasses, ServerSignatureIds), (client, clientClasses, ClientSignatureIds)
                })
                {
                    var scheme = Number(report, local ? "local_handshake_signature_id" : "handshake_signature_id");
                    if (scheme >= 0)
                    {
                        ids.Add(scheme);
                        classes.Add(Text(report, local ? "local_authentication_class" : "authentication_class"));
                    }
                }
            }
        }
        Completion = completions.Contains(true) && completions.Contains(false) ? "Conflicting" :
            completions.Contains(true) ? "Completed" : completions.Contains(false) ? "Failed" : "Not confirmed";
        PeerVerification = verifications.Contains(1) && verifications.Contains(0) ? "Conflicting" :
            verifications.Contains(0) ? "Unverified" : verifications.Contains(1) && verifications.All(value => value == 1) ?
            "Verified" : "Not reported";
        if (Tls is > 0 and < 772)
        {
            foreach (var (name, classes, ids) in new[]
            {
                ("handshake_signature", serverClasses, ServerSignatureIds),
                ("client_handshake_signature", clientClasses, ClientSignatureIds)
            })
            {
                var signature = Text(crypto, name);
                if (signature.Length == 0)
                    continue;
                classes.Add(SignatureClass(signature));
                if (SignatureId(signature) is >= 0 and var id)
                    ids.Add(id);
            }
            if (serverClasses.Count == 0 && authentication is "RSA" or "ECDSA" or "DSS" or "DSA")
                serverClasses.Add("Classical");
        }
        ServerAuth = Classify(serverClasses);
        ClientAuth = Classify(clientClasses);
        if (serverClasses.Count == 0 && Text(crypto, "selected_psk_index") is not ("" or "-1" or "null"))
            ServerAuth = "PSK selected";
        foreach (var certificate in string.Join(',', reportedCertificates.Prepend(certificateFacts))
            .Split(',', StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal))
        {
            var fields = certificate.Split('|');
            if (fields.Length == 5)
                Certificates.Add(new(fields[0], fields[1], fields[2], fields[3], fields[4]));
        }
        ChainSignatures = Classify(Certificates.Where(certificate => certificate.Role == "server")
            .Select(certificate => certificate.SignatureClass));
        CertificateKeys = Classify(Certificates.Where(certificate => certificate.Role == "server")
            .Select(certificate => certificate.KeyClass));
        if (KeyClass is "Unknown" or "Not observed" or "PSK only")
            MissingEvidence.Add("Key establishment is unknown or PSK provenance is unavailable");
        if (ServerAuth is "Unknown" or "Not observed" or "PSK selected")
            MissingEvidence.Add(Tls == 772 ? "Server authentication requires endpoint evidence" :
                "Server authentication was not established from observed messages");
        if (ChainSignatures is "Unknown" or "Not observed")
            MissingEvidence.Add("Server certificate signature evidence is absent or unsupported");
        if (Completion == "Not confirmed")
            MissingEvidence.Add("Handshake completion requires endpoint evidence");
        if (Text(crypto, "negotiation_history_truncated") is "True" or "true" or "1")
            MissingEvidence.Add("Negotiation history reached its inspection limit");
        if (EchOffered)
            MissingEvidence.Add("ECH may conceal the actual server name");
        CountKeys = ["Key establishment: " + KeyClass, "Server authentication: " + ServerAuth,
            "Client authentication: " + ClientAuth, "Presented server-chain signatures: " + ChainSignatures,
            "Presented server certificate keys: " + CertificateKeys, "Completion: " + Completion,
            "Peer verification: " + PeerVerification, "Group standardization: " +
                (GroupStatus.Length == 0 ? "Not recorded" : GroupStatus),
            "Evidence source: " + EvidenceSource,
            .. MissingEvidence.Select(missing => "Evidence gaps: " + missing)];
        return this;
    }

    private static string Classify(IEnumerable<string> values)
    {
        var classes = values.Distinct(StringComparer.Ordinal).ToArray();
        if (classes.Length == 0)
            return "Not observed";
        if (classes.Any(value => value is not ("Classical" or "Post-quantum")))
            return "Unknown";
        return classes.Length > 1 ? "Mixed classical/PQ" : classes[0];
    }

    private static readonly Dictionary<string, int> SignatureIds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["rsa_pkcs1_sha1"] = 0x0201, ["dsa_sha1"] = 0x0202, ["ecdsa_sha1"] = 0x0203,
        ["rsa_pkcs1_sha256"] = 0x0401, ["dsa_sha256"] = 0x0402, ["ecdsa_secp256r1_sha256"] = 0x0403,
        ["rsa_pkcs1_sha384"] = 0x0501, ["ecdsa_secp384r1_sha384"] = 0x0503,
        ["rsa_pkcs1_sha512"] = 0x0601, ["ecdsa_secp521r1_sha512"] = 0x0603,
        ["rsa_pss_rsae_sha256"] = 0x0804, ["rsa_pss_rsae_sha384"] = 0x0805, ["rsa_pss_rsae_sha512"] = 0x0806,
        ["ed25519"] = 0x0807, ["ed448"] = 0x0808, ["rsa_pss_pss_sha256"] = 0x0809,
        ["rsa_pss_pss_sha384"] = 0x080a, ["rsa_pss_pss_sha512"] = 0x080b,
        ["mldsa44"] = 0x0904, ["mldsa65"] = 0x0905, ["mldsa87"] = 0x0906
    };
    private static int SignatureId(string name) => SignatureIds.GetValueOrDefault(name, -1);
    private static string SignatureClass(string name) => SignatureId(name) is >= 0x0904 and <= 0x0906 ||
        name.StartsWith("slhdsa_", StringComparison.OrdinalIgnoreCase) ? "Post-quantum" :
        SignatureId(name) >= 0 ? "Classical" : "Unknown";
}

public sealed class ReadinessRow
{
    public string Key { get; set; } = "";
    public string Computer { get; set; } = "";
    public string Application { get; set; } = "";
    public string Peer { get; set; } = "";
    public string Transport { get; set; } = "";
    public long Total { get; set; }
    public long FirstUs { get; set; } = long.MaxValue;
    public long LastUs { get; set; }
    public Dictionary<string, long> Counts { get; set; } = new(StringComparer.Ordinal);
    public long Count(string category, string value) => Counts.GetValueOrDefault(category + ": " + value);
    internal void Add(string category, string value, long count = 1)
    {
        var key = category + ": " + value;
        Counts[key] = Counts.GetValueOrDefault(key) + count;
    }
    public long PqKeys => Count("Key establishment", "Hybrid post-quantum") + Count("Key establishment", "Post-quantum");
    public long ClassicalKeys => Count("Key establishment", "Classical");
    public long UnknownKeys => Total - PqKeys - ClassicalKeys;
    public long PqAuth => Count("Server authentication", "Post-quantum");
    public long ClassicalAuth => Count("Server authentication", "Classical") + Count("Server authentication", "Mixed classical/PQ");
    public long UnknownAuth => Total - PqAuth - ClassicalAuth;
    public long Complete => Count("Completion", "Completed");
    public long Failures => Count("Completion", "Failed");
}

public sealed class PolicySummary
{
    public string Name { get; init; } = "";
    public long Applicable { get; set; }
    public long Pass { get; set; }
    public long Violations { get; set; }
    public long Insufficient { get; set; }
    public Dictionary<string, long> Issues { get; } = new(StringComparer.Ordinal);
    public List<PolicyExample> Examples { get; } = [];
}
public sealed record PolicyExample(long Id, string Computer, string Application, string Peer, string Status, string Reasons,
    string EndpointEventId = "");
public sealed record CoverageRow(string Computer, long Sessions, long Packets, long Losses, long Truncated,
    long InspectionLimits, long LastUpdatedUs, string Status);
public sealed record PqcSnapshot(string DatabaseId, long Revision, string ScopeKey, long FromUs, long ToUs,
    List<ReadinessRow> Rows, List<PolicySummary> Policies, List<CoverageRow> Coverage, List<string> RuleVersions)
{
    public long Total => Rows.Sum(row => row.Total);
    public long PolicyObservations { get; init; }
    public long FirstPolicyUs { get; init; } = long.MaxValue;
}

internal static class ObservationSql
{
    internal static string Where(DatabaseSource source, Query query, DbCommand command, long since = 0, long until = long.MaxValue)
    {
        var filters = InvestigationSql.Conditions(source, query, command, false);
        (since, until) = InvestigationSql.Bounds(query, since, until);
        void Parameter(string name, object value) => DatabaseSource.AddParameter(command, name, value);
        if (since > 0)
        {
            filters.Add("c.first_us>=@since");
            Parameter("@since", since);
        }
        if (until < long.MaxValue)
        {
            filters.Add("c.first_us<=@until");
            Parameter("@until", until);
        }
        if (query.Protocol.Length > 0)
        {
            filters.Add("c.tls_name=@version");
            Parameter("@version", query.Protocol);
        }
        if (query.Incomplete)
            filters.Add("c.state IN ('client_hello_only','server_hello_only','retry_only','ssh_identification'," +
                "'ssh_kex_offers','ssh_kex_selection','ssh_no_common_algorithm','wireguard_initiation'," +
                "'ike_sa_offers','openvpn_control','openvpn_tls_client_hello')");
        if (query.Search.Length > 0)
        {
            var columns = new[]
            {
                "c.sni", "c.source_address", "c.destination_address", "c.source_process", "c.destination_process",
                "s.computer_name", "c.source_account", "c.source_account_domain", "c.source_account_sid",
                "c.destination_account", "c.destination_account_domain", "c.destination_account_sid",
                "CONCAT(c.source_account_domain,'\\',c.source_account)",
                "CONCAT(c.destination_account_domain,'\\',c.destination_account)",
                "c.group_name", "c.cipher_name", "c.tls_name", "c.key_exchange",
                "c.authentication", "c.psk_mode", "c.encryption", "c.alert", "c.certificate_sha256", "c.state"
            };
            var jsonFields = new[] { "transport", "handshake_confirmation", "group_class" };
            string Matches(string field) => source.TextMatch(field, "@pattern");
            var jsonValues = source.Provider switch
            {
                DatabaseProvider.SqlServer => "OPENJSON(c.crypto_json) WITH (" +
                    string.Join(',', jsonFields.Select(field => $"[{field}] NVARCHAR(MAX) '$.{field}'")) + ") evidence",
                DatabaseProvider.PostgreSql => "JSONB_TO_RECORD(c.crypto_json::jsonb) AS evidence(" +
                    string.Join(',', jsonFields.Select(field => field + " TEXT")) + ")",
                _ => ""
            };
            var jsonMatches = jsonValues.Length > 0 ? "EXISTS (SELECT 1 FROM " + jsonValues + " WHERE " +
                string.Join(" OR ", jsonFields.Select(field => Matches(field == "transport" ?
                    "COALESCE(evidence.transport,'TCP')" : "evidence." + field))) + ")" :
                string.Join(" OR ", jsonFields.Select(field => Matches(field == "transport" ?
                    $"COALESCE({source.JsonText(field)},'TCP')" : source.JsonText(field))));
            filters.Add("(" + string.Join(" OR ", columns.Select(Matches)) + " OR " + jsonMatches + ")");
            Parameter("@pattern", "%" + query.Search.Replace("\\", "\\\\").Replace("%", "\\%")
                .Replace("_", "\\_").Replace("[", "\\[") + "%");
        }
        return filters.Count == 0 ? "1=1" : string.Join(" AND ", filters);
    }
}

public static class PqcInsights
{
    public static readonly string[] Dimensions = ["Client application", "Server application", "Collector computer", "Server name"];
    internal static readonly string[] ProfileFields = ["transport", "selected_group_id", "group_class", "group_standardization",
        "classification_rule_version", "selected_psk_index", "handshake_signature", "client_handshake_signature",
        "negotiation_history_truncated", "evidence_source", "endpoint_confirmations"];
    internal static readonly string[] EndpointFields = ["local_role", "success", "peer_verified", "handshake_signature_id",
        "authentication_class", "local_handshake_signature_id", "local_authentication_class", "certificate_facts"];

    internal static string CertificateFacts(DatabaseSource source)
    {
        var fields = new[] { "public_key_oid", "signature_oid", "public_key_class", "certificate_signature_class" };
        var value = "CONCAT(l.role,'|'," + string.Join(",'|',", fields.Select(field =>
            $"COALESCE({source.JsonValue("p.metadata_json", field)},'')")) + ")";
        var aggregate = source.Provider switch
        {
            DatabaseProvider.SqlServer => $"STRING_AGG(CAST({value} AS NVARCHAR(MAX)),',') WITHIN GROUP (ORDER BY l.role,l.chain_index)",
            DatabaseProvider.PostgreSql => $"STRING_AGG({value},',' ORDER BY l.role,l.chain_index)",
            _ => $"GROUP_CONCAT({value},',')"
        };
        return $"(SELECT {aggregate} FROM {source.Prefix}connection_certificates l JOIN " +
            $"{source.Prefix}certificates p ON p.sha256=l.sha256 WHERE l.run_id=c.run_id AND l.flow_id=c.flow_id)";
    }

    private static string CryptoProfile(DatabaseSource source)
    {
        if (source.Provider == DatabaseProvider.Sqlite)
            return "JSON_EXTRACT(c.crypto_json," + string.Join(',', ProfileFields.Select(field => $"'$.{field}'")) + ")";
        if (source.Provider == DatabaseProvider.SqlServer)
        {
            // Explicit JSON schemas parse each document once instead of repeating scalar extraction.
            var endpointSchema = string.Join(',', EndpointFields.Select(field => $"[{field}] " +
                (field == "success" ? "BIT" : field.EndsWith("_id") || field == "peer_verified" ? "INT" : "NVARCHAR(MAX)") +
                $" '$.{field}'"));
            var fields = ProfileFields[..^1];
            var profileSchema = string.Join(',', fields.Select(field => $"[{field}] NVARCHAR(MAX) '$.{field}'")) +
                ",[endpoint_confirmations] NVARCHAR(MAX) '$.endpoint_confirmations' AS JSON";
            var serverReports = "(SELECT " + string.Join(',', EndpointFields.Select(field => $"e.[{field}]")) +
                $" FROM OPENJSON(x.endpoint_confirmations) WITH ({endpointSchema}) e " +
                "FOR JSON PATH,INCLUDE_NULL_VALUES)";
            return "(SELECT " + string.Join(',', fields.Select(field => $"x.[{field}]")) +
                $",JSON_QUERY({serverReports}) AS [endpoint_confirmations] FROM OPENJSON(c.crypto_json) " +
                $"WITH ({profileSchema}) x FOR JSON PATH,WITHOUT_ARRAY_WRAPPER,INCLUDE_NULL_VALUES)";
        }
        if (source.Provider != DatabaseProvider.PostgreSql)
            throw new ArgumentException("Unsupported database provider.");
        // Record projection keeps PostgreSQL from reparsing the text document for every field.
        var projected = ProfileFields[..^1];
        var schema = string.Join(',', projected.Select(field => field + " TEXT")) + ",endpoint_confirmations JSONB";
        var endpointPairs = string.Join(',', EndpointFields.Select(field => $"'{field}',e.value->'{field}'"));
        var reports = $"(SELECT JSONB_AGG(JSONB_BUILD_OBJECT({endpointPairs})) FROM " +
            "JSONB_ARRAY_ELEMENTS(COALESCE(NULLIF(x.endpoint_confirmations,'null'::jsonb),'[]'::jsonb)) e(value))";
        var pairs = string.Join(',', projected.Select(field => $"'{field}',x.{field}"));
        return $"(SELECT JSONB_BUILD_OBJECT({pairs},'endpoint_confirmations',COALESCE({reports},'[]'::jsonb))::text " +
            $"FROM JSONB_TO_RECORD(c.crypto_json::jsonb) x({schema}))";
    }

    private static string NormalizeProfile(string json)
    {
        // Exclude report identifiers and timestamps from the bounded assessment cache.
        using var document = JsonDocument.Parse(json);
        var profile = document.RootElement;
        var reports = profile[ProfileFields.Length - 1];
        if (reports.ValueKind != JsonValueKind.Array || reports.GetArrayLength() == 0)
            return json;
        var builder = new StringBuilder(384);
        builder.Append('[');
        for (var index = 0; index < ProfileFields.Length - 1; ++index)
            builder.Append(profile[index].GetRawText()).Append(',');
        builder.Append('[');
        if (reports.ValueKind == JsonValueKind.Array)
        {
            var first = true;
            foreach (var report in reports.EnumerateArray())
            {
                if (!first)
                    builder.Append(',');
                first = false;
                builder.Append('[');
                for (var index = 0; index < EndpointFields.Length; ++index)
                {
                    if (index > 0)
                        builder.Append(',');
                    builder.Append(report.TryGetProperty(EndpointFields[index], out var value) ? value.GetRawText() : "null");
                }
                builder.Append(']');
            }
        }
        return builder.Append("]]").ToString();
    }

    private sealed class Assessment(FlowEvidence flow, FlowEvidence evidence, int port)
    {
        public FlowEvidence Flow { get; } = flow;
        public FlowEvidence Evidence { get; } = evidence;
        public int Port { get; } = port;
        public long Count { get; set; }
        public long FirstUs { get; set; } = long.MaxValue;
        public long LastUs { get; set; }
    }

    public static PqcSnapshot Read(DatabaseSource source, Query query, long sinceUs, long untilUs,
        string dimension, IReadOnlyList<CryptoPolicy> policies, CancellationToken cancellation)
    {
        (sinceUs, untilUs) = InvestigationSql.Bounds(query, sinceUs, untilUs);
        if (!Dimensions.Contains(dimension) || policies.Count > 128)
            throw new ArgumentException("Choose a supported readiness dimension and at most 128 policies.");
        var compiled = policies.Where(policy => policy.Enabled).Select(policy => new CompiledPolicy(policy)).ToArray();
        var summaries = compiled.Select(policy => new PolicySummary { Name = policy.Policy.Name }).ToList();
        var assets = new Dictionary<string, ReadinessRow>(StringComparer.OrdinalIgnoreCase);
        var normalizedProfiles = new Dictionary<string, string>(StringComparer.Ordinal);
        var evidenceCache = new Dictionary<(string Json, string Certificates, string Exchange, string Authentication, int Tls, bool Ech), FlowEvidence>();
        var profiles = new Dictionary<(string Computer, string Client, string ClientPath, string Server,
            string ServerPath, string Peer, int Port, FlowEvidence Evidence), Assessment>();
        var rules = new HashSet<string>(StringComparer.Ordinal);
        var policyObservations = 0L;
        var firstPolicyUs = long.MaxValue;
        var policyResults = new Dictionary<(FlowEvidence Evidence, int Policy), PolicyResult>();
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var transaction = connection is Microsoft.Data.Sqlite.SqliteConnection sqlite ?
            sqlite.BeginTransaction(deferred: true) : connection.BeginTransactionAsync(cancellation).GetAwaiter().GetResult();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 30 : 60;
        command.CommandText = $"SELECT {(source.Provider == DatabaseProvider.Sqlite ? "database_id" : "'server'")},revision " +
            $"FROM {source.Prefix}metadata WHERE id=1";
        string databaseId;
        long revision;
        using (var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            reader.ReadAsync(cancellation).GetAwaiter().GetResult();
            databaseId = source.Provider == DatabaseProvider.Sqlite ? reader.GetString(0) :
                Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(source.Provider + ":" + source.DisplayName)));
            revision = Convert.ToInt64(reader[1]);
        }
        // TLS policies and certificate readiness apply to TLS and DTLS, including partial hellos.
        var where = ObservationSql.Where(source, query, command, sinceUs, untilUs) +
            " AND c.tls_name NOT IN ('SSH 2.0','Unknown','WireGuard','IKEv2','OpenVPN','SMB','RDP','TDS','Kerberos')";
        var fields = new[] { "computer_name", "source_process", "source_path", "destination_process", "destination_path",
            "sni", "destination_address", "destination_port", "tls_version", "group_name", "key_exchange", "authentication",
            "crypto_profile", "certificate_facts", "ech_offered" };
        var count = source.Provider == DatabaseProvider.SqlServer ? "COUNT_BIG(*)" : "COUNT(*)";
        var profileSource = $"{source.Prefix}connections c JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id WHERE {where}";
        command.CommandText = $"""
            WITH profiles AS
            (SELECT c.id,c.first_us,c.last_us,s.computer_name,c.source_process,c.source_path,c.destination_process,
                c.destination_path,c.sni,c.destination_address,c.destination_port,c.tls_version,c.group_name,
                c.key_exchange,c.authentication,{CryptoProfile(source)} AS crypto_profile,
                {CertificateFacts(source)} AS certificate_facts,c.ech_offered
                FROM {profileSource})
            SELECT MIN(id),MIN(first_us),{string.Join(',', fields)},{count},MAX(last_us)
                FROM profiles GROUP BY {string.Join(',', fields)}
            """;
        if (source.Provider == DatabaseProvider.Sqlite)
            command.CommandText = $"""
                SELECT c.id,c.first_us,s.computer_name,c.source_process,c.source_path,c.destination_process,
                    c.destination_path,c.sni,c.destination_address,c.destination_port,c.tls_version,c.group_name,
                    c.key_exchange,c.authentication,{CryptoProfile(source)},{CertificateFacts(source)},c.ech_offered,1,c.last_us
                FROM {profileSource}
                """;
        // Coalesce equivalent evidence and scope before evaluating policies and updating histograms.
        void Assess(Assessment profile)
        {
            cancellation.ThrowIfCancellationRequested();
            var flow = profile.Flow with { FirstUs = profile.FirstUs };
            var observations = profile.Count;
            var lastUs = profile.LastUs;
            var application = dimension == "Server application" ?
                (flow.ServerPath.Length > 0 ? flow.ServerPath : flow.ServerProcess) :
                (flow.ClientPath.Length > 0 ? flow.ClientPath : flow.ClientProcess);
            if (application.Length == 0 && dimension == "Client application")
                application = flow.EndpointPath.Length > 0 ? flow.EndpointPath : flow.EndpointProcess;
            var peer = flow.ServerName + (profile.Port > 0 ? ":" + profile.Port : "");
            var attributed = dimension == "Server application" ? flow.ServerProcess.Length > 0 || flow.ServerPath.Length > 0 :
                flow.ClientProcess.Length > 0 || flow.ClientPath.Length > 0;
            if (dimension is "Collector computer" or "Server name")
                attributed = flow.ClientProcess.Length > 0 || flow.ClientPath.Length > 0 ||
                    flow.ServerProcess.Length > 0 || flow.ServerPath.Length > 0;
            if (flow.EndpointProcess.Length > 0 || flow.EndpointPath.Length > 0)
                attributed = true;
            if (dimension == "Collector computer")
                application = peer = "";
            else if (dimension == "Server name")
                application = "";
            var key = string.Join('\u001f', flow.Computer, application, peer, flow.Transport);
            ReadinessRow? asset = null;
            if (flow.Protocol is "TLS" or "DTLS")
            {
                rules.Add(flow.RuleVersion);
                if (!assets.TryGetValue(key, out asset))
                {
                    if (assets.Count >= 20000)
                        throw new InvalidDataException(
                            "Readiness scope exceeds 20,000 cohorts. Narrow the search or time window.");
                    asset = new ReadinessRow { Key = key, Computer = flow.Computer,
                        Application = application.Length == 0 && dimension.EndsWith("application") ?
                            "Unattributed" : application,
                        Peer = peer, Transport = flow.Transport };
                    assets.Add(key, asset);
                }
                asset.Total += observations;
                asset.FirstUs = Math.Min(asset.FirstUs, flow.FirstUs);
                asset.LastUs = Math.Max(asset.LastUs, lastUs);
                foreach (var countKey in flow.CountKeys)
                    asset.Counts[countKey] = asset.Counts.GetValueOrDefault(countKey) + observations;
                asset.Add("Process attribution", attributed ? "Attributed" : "Unattributed", observations);
            }
            var statuses = new HashSet<string>();
            for (var index = 0; index < compiled.Length; ++index)
            {
                if (!compiled[index].Policy.Applies(flow))
                    continue;
                var policyKey = (profile.Evidence, index);
                if (!policyResults.TryGetValue(policyKey, out var result))
                {
                    if (policyResults.Count >= 8192)
                        policyResults.Clear();
                    result = compiled[index].Evaluate(flow)!;
                    policyResults.Add(policyKey, result);
                }
                var summary = summaries[index];
                summary.Applicable += observations;
                if (result.Status == "Pass")
                    summary.Pass += observations;
                else if (result.Status == "Violation")
                    summary.Violations += observations;
                else
                    summary.Insufficient += observations;
                statuses.Add(result.Status);
                foreach (var issue in result.Issues)
                {
                    var issueKey = issue.Status + ": " + issue.Message;
                    summary.Issues[issueKey] = summary.Issues.GetValueOrDefault(issueKey) + observations;
                }
                if (result.Status != "Pass" && summary.Examples.Count < 250)
                    summary.Examples.Add(new(flow.Id, flow.Computer, application, peer, result.Status,
                        string.Join("; ", result.Issues.Select(issue => issue.Message)), flow.EndpointEventId));
            }
            if (statuses.Count > 0)
            {
                policyObservations += observations;
                firstPolicyUs = Math.Min(firstPolicyUs, flow.FirstUs);
            }
            asset?.Add("Policy results", statuses.Contains("Violation") ? "Violation" :
                statuses.Contains("Insufficient evidence") ? "Insufficient evidence" :
                statuses.Contains("Pass") ? "Pass" : "No applicable policy", observations);
        }
        void FlushProfiles()
        {
            foreach (var profile in profiles.Values)
                Assess(profile);
            profiles.Clear();
        }
        using var registration = cancellation.Register(command.Cancel);
        using (var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                cancellation.ThrowIfCancellationRequested();
                string Text(int ordinal) => reader.IsDBNull(ordinal) ? "" : reader.GetString(ordinal);
                var json = Text(14);
                if (source.Provider == DatabaseProvider.Sqlite)
                {
                    if (!normalizedProfiles.TryGetValue(json, out var normalized))
                    {
                        normalized = NormalizeProfile(json);
                        if (normalizedProfiles.Count >= 256)
                            normalizedProfiles.Clear();
                        if (json.Length <= 4096)
                            normalizedProfiles.Add(json, normalized);
                    }
                    json = normalized;
                }
                var evidenceKey = (json,
                    Text(15), Text(12), Text(13), reader.IsDBNull(10) ? 0 : Convert.ToInt32(reader[10]),
                    Convert.ToInt32(reader[16]) != 0);
                if (!evidenceCache.TryGetValue(evidenceKey, out var evidence))
                {
                    if (evidenceCache.Count >= 4096)
                    {
                        FlushProfiles();
                        evidenceCache.Clear();
                        policyResults.Clear();
                    }
                    evidence = new FlowEvidence { Tls = evidenceKey.Item5, EchOffered = evidenceKey.Item6 }
                        .Decode(evidenceKey.Item1, evidenceKey.Item2, evidenceKey.Item3, evidenceKey.Item4);
                    evidenceCache.Add(evidenceKey, evidence);
                }
                var sni = Text(7);
                var key = (Text(2), Text(3), Text(4), Text(5), Text(6),
                    sni.Length > 0 ? sni : Text(8), Convert.ToInt32(reader[9]), evidence);
                if (!profiles.TryGetValue(key, out var profile))
                {
                    if (profiles.Count >= 4096)
                        FlushProfiles();
                    profile = new Assessment(evidence with
                    {
                        Id = Convert.ToInt64(reader[0]), Computer = key.Item1, ClientProcess = key.Item2,
                        ClientPath = key.Item3, ServerProcess = key.Item4, ServerPath = key.Item5,
                        ServerName = key.Item6, GroupName = Text(11)
                    }, evidence, key.Item7);
                    profiles.Add(key, profile);
                }
                profile.Count += Convert.ToInt64(reader[17]);
                profile.FirstUs = Math.Min(profile.FirstUs, Convert.ToInt64(reader[1]));
                profile.LastUs = Math.Max(profile.LastUs, Convert.ToInt64(reader[18]));
            }
        }
        FlushProfiles();

        // Protocol policy observations remain outside the TLS readiness denominator.
        if (compiled.Any(policy => policy.Policy.Protocol != PolicyProtocol.Tls))
        {
            command.Parameters.Clear();
            var protocolWhere = ObservationSql.Where(source, query, command, sinceUs, untilUs) +
                " AND c.tls_name IN ('SSH 2.0','SMB','WireGuard','IKEv2','OpenVPN')";
            command.CommandText = $"""
                SELECT c.id AS policy_observation_id,c.run_id,c.flow_id,c.first_us,c.last_us,s.computer_name AS computer,
                    c.source_process,c.source_path,c.destination_process,c.destination_path,c.sni,
                    c.destination_address,c.destination_port,c.tls_version,c.group_name,c.key_exchange,c.authentication,
                    c.ech_offered AS policy_ech_offered,c.tls_name AS policy_protocol,
                    '' AS policy_certificate_facts,c.crypto_json AS metadata_json
                FROM {source.Prefix}connections c JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id
                WHERE {protocolWhere}
                """;
            using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                cancellation.ThrowIfCancellationRequested();
                var flow = PolicyEvaluator.ConnectionEvidence(reader, reader.GetString(reader.GetOrdinal("computer")));
                Assess(new Assessment(flow, flow, Convert.ToInt32(reader["destination_port"]))
                {
                    Count = 1, FirstUs = flow.FirstUs, LastUs = Convert.ToInt64(reader["last_us"])
                });
            }
        }
        // Count unassociated endpoint reports once, retaining their provenance and unknown fields.
        command.Parameters.Clear();
        var assessment = source.Provider == DatabaseProvider.SqlServer ? "JSON_QUERY(e.detail_json,'$.assessment')" :
            source.JsonValue("e.detail_json", "assessment");
        var matchedRun = source.JsonValue("e.detail_json", "matched_run_id");
        var matchedFlow = source.JsonValue("e.detail_json", "matched_flow_id");
        var endpointWhere = InvestigationSql.EndpointWhere(source, query, command, sinceUs, untilUs, true);
        command.CommandText = $"""
            SELECT e.id,s.computer_name,e.detail_json,e.protocol,e.cipher,e.peer,e.port
            FROM {source.Prefix}endpoint_events e JOIN {source.Prefix}capture_sessions s ON s.id=e.run_id
            WHERE {endpointWhere} AND {assessment} IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM {source.Prefix}connections c
                    WHERE c.run_id={matchedRun} AND c.flow_id=CAST({matchedFlow} AS BIGINT))
            """;
        using (var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                cancellation.ThrowIfCancellationRequested();
                using var document = JsonDocument.Parse(reader.GetString(2));
                var detail = document.RootElement.GetProperty("assessment");
                string Text(string name) => detail.TryGetProperty(name, out var value) ? value.ToString() : "";
                var firstUs = detail.GetProperty("first_us").GetInt64();
                if (firstUs < sinceUs || firstUs > untilUs || query.Incomplete ||
                    query.Protocol.Length > 0 && query.Protocol != reader.GetString(3))
                    continue;
                var role = Text("local_role");
                var process = Text("process");
                var path = Text("path");
                var flow = new FlowEvidence
                {
                    FirstUs = firstUs, Computer = reader.GetString(1), EndpointEventId = reader.GetString(0),
                    ClientProcess = role == "Client" ? process : "", ClientPath = role == "Client" ? path : "",
                    ServerProcess = role == "Server" ? process : "", ServerPath = role == "Server" ? path : "",
                    EndpointProcess = role == "Unknown" ? process : "", EndpointPath = role == "Unknown" ? path : "",
                    ServerName = Text("server_name"), GroupName = Text("group_name"),
                    Tls = detail.GetProperty("tls_version").GetInt32()
                }.Decode(detail.GetProperty("crypto").GetRawText(), Text("certificate_facts"),
                    Text("key_exchange"), Text("authentication"));
                var profile = new Assessment(flow, flow, detail.GetProperty("server_port").GetInt32())
                {
                    Count = 1, FirstUs = firstUs, LastUs = detail.GetProperty("last_us").GetInt64()
                };
                Assess(profile);
            }
        }
        command.Parameters.Clear();
        command.CommandText = $"""
            SELECT computer_name,COUNT(*),SUM(packets),SUM(capture_lost+queue_lost+storage_lost+process_events_lost+telemetry_lost),
                SUM(truncated),SUM(flow_limit+reassembly_limit),MAX(updated_us)
            FROM {source.Prefix}capture_sessions WHERE started_us<=@until AND (stopped_us IS NULL OR stopped_us>=@since)
            GROUP BY computer_name
            """;
        DatabaseSource.AddParameter(command, "@since", sinceUs);
        DatabaseSource.AddParameter(command, "@until", untilUs);
        var coverage = new List<CoverageRow>();
        using (var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
                coverage.Add(new(reader.GetString(0), Convert.ToInt64(reader[1]), Convert.ToInt64(reader[2]),
                    Convert.ToInt64(reader[3]), Convert.ToInt64(reader[4]), Convert.ToInt64(reader[5]),
                    Convert.ToInt64(reader[6]), "Session totals; not apportioned to filters"));
        }
        transaction.CommitAsync(cancellation).GetAwaiter().GetResult();
        return new(databaseId, revision, query.ScopeKey + '\u001f' + dimension,
            sinceUs, untilUs, assets.Values.OrderByDescending(row => row.Total).ThenBy(row => row.Key).ToList(), summaries,
            coverage, rules.Order().ToList())
        { PolicyObservations = policyObservations, FirstPolicyUs = firstPolicyUs };
    }
}
