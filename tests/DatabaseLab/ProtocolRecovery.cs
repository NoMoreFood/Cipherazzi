using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

internal static class ProtocolRecovery
{
    public static async Task RunAsync(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "protocol-recovery.db");
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        {
            original.Open();
            connection.Open();
            original.BackupDatabase(connection);
        }
        using var command = connection.CreateCommand();

        // Keep one damaged observation beside a healthy peer in every policy and export query.
        command.CommandText = "PRAGMA table_info(connections)";
        var columns = new List<string>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                if (reader.GetString(1) != "id")
                    columns.Add(reader.GetString(1));
        command.CommandText = "DELETE FROM connection_certificates; DELETE FROM endpoint_certificates; " +
            "DELETE FROM endpoint_events; DELETE FROM connections WHERE id<>(SELECT min(id) FROM connections);" +
            "INSERT INTO connections(" + string.Join(',', columns) + ") SELECT " +
            string.Join(',', columns.Select(column => column == "flow_id" ? "c.flow_id+1" : "c." + column)) +
            " FROM connections c";
        command.ExecuteNonQuery();
        var provider = Array.IndexOf(args, "--provider");
        var source = provider < 0 ? DatabaseSource.Sqlite(path) :
            DatabaseSource.FromEnvironment(args[provider + 1], "CIPHERAZZI_CONNECTION");
        if (source.Provider != DatabaseProvider.Sqlite)
        {
            var database = source.Provider == DatabaseProvider.SqlServer ?
                new SqlConnectionStringBuilder(source.ConnectionString).InitialCatalog :
                new NpgsqlConnectionStringBuilder(source.ConnectionString).Database;
            if (database?.StartsWith("CipherazziProtocol_", StringComparison.Ordinal) != true)
                throw new InvalidOperationException("Use an isolated CipherazziProtocol_ database.");
            await Replication.InitializeAsync(source, CancellationToken.None);
        }
        var query = new Query("", "", false, PageCursor.Newest);
        var cases = new List<object>();
        var failures = 0;
        foreach (var (name, protocol, field, value, expected) in new[]
        {
            ("ssh-null", "SSH", "cipher", "null", "Insufficient evidence"),
            ("ssh-array", "SSH", "cipher", "[]", "Insufficient evidence"),
            ("ssh-object", "SSH", "cipher", "{}", "Insufficient evidence"),
            ("ssh-number", "SSH", "cipher", "123", "Insufficient evidence"),
            ("ssh-boolean", "SSH", "cipher", "true", "Insufficient evidence"),
            ("ssh-unicode", "SSH", "cipher", "\"\\ud800\"", "Insufficient evidence"),
            ("ssh-bits-object", "SSH", "bits", "{}", "Insufficient evidence"),
            ("ssh-bits-unicode", "SSH", "bits", "\"\\ud800\"", "Insufficient evidence"),
            ("ssh-bits-overflow", "SSH", "bits", "2147483648", "Insufficient evidence"),
            ("ssh-bits-fraction", "SSH", "bits", "256.5", "Insufficient evidence"),
            ("ssh-bits-small", "SSH", "bits", "128", "Violation"),
            ("smb-text", "SMB", "cipher", "[\"bogus\"]", "Insufficient evidence"),
            ("smb-null", "SMB", "cipher", "[null]", "Insufficient evidence"),
            ("smb-array", "SMB", "cipher", "[[]]", "Insufficient evidence"),
            ("smb-object", "SMB", "cipher", "[{}]", "Insufficient evidence"),
            ("smb-fraction", "SMB", "cipher", "[2.5]", "Insufficient evidence"),
            ("smb-overflow", "SMB", "cipher", "[65536]", "Insufficient evidence"),
            ("smb-list", "SMB", "cipher", "[\"1,2\"]", "Insufficient evidence"),
            ("smb-boolean", "SMB", "cipher", "[true]", "Insufficient evidence"),
            ("smb-unicode", "SMB", "cipher", "[\"\\udc00\"]", "Insufficient evidence"),
            ("smb-partial", "SMB", "cipher", "[\"0x0002\",null]", "Insufficient evidence"),
            ("smb-partial-violation", "SMB", "cipher", "[\"0x0001\",null]", "Violation"),
            ("smb-numeric", "SMB", "cipher", "[2]", "Pass"),
            ("smb-decimal-string", "SMB", "cipher", "[\"2\"]", "Pass"),
            ("smb-unapproved", "SMB", "cipher", "[1]", "Violation"),
            ("smb-signing-algorithm-null", "SMB", "algorithm", "[null]", "Insufficient evidence"),
            ("smb-signing-algorithm-partial-violation", "SMB", "algorithm", "[1,null]", "Violation"),
            ("smb-dialect-unicode", "SMB", "dialect", "\"\\ud800\"", "Insufficient evidence"),
            ("smb-dialect-object", "SMB", "dialect", "{}", "Insufficient evidence"),
            ("smb-dialect-small", "SMB", "dialect", "\"0x0202\"", "Violation"),
            ("smb-signing-string", "SMB", "signing", "\"True\"", "Insufficient evidence"),
            ("smb-signing-false", "SMB", "signing", "false", "Violation"),
            ("smb-signing-observed", "SMB", "signed", "\"True\"", "Insufficient evidence"),
            ("smb-encryption-observed", "SMB", "encrypted", "\"True\"", "Insufficient evidence"),
            ("ldap-unicode", "LDAP", "protection", "\"\\ud800\"", "Insufficient evidence"),
            ("ldap-object", "LDAP", "protection", "{}", "Insufficient evidence"),
            ("ldap-none", "LDAP", "protection", "\"None\"", "Violation"),
            ("ike-unicode", "IKEv2", "cipher", "\"\\ud800\"", "Insufficient evidence"),
            ("ike-array", "IKEv2", "cipher", "[]", "Insufficient evidence"),
            ("ike-bits-unicode", "IKEv2", "bits", "\"\\ud800\"", "Insufficient evidence"),
            ("ike-bits-small", "IKEv2", "bits", "128", "Violation"),
            ("wireguard-unicode", "WireGuard", "cipher", "\"\\ud800\"", "Insufficient evidence"),
            ("wireguard-bits-boolean", "WireGuard", "bits", "true", "Insufficient evidence"),
            ("openvpn-unicode", "OpenVPN", "cipher", "\"\\ud800\"", "Insufficient evidence"),
            ("openvpn-version-unicode", "OpenVPN", "version", "\"\\ud800\"", "Insufficient evidence"),
            ("openvpn-version-small", "OpenVPN", "version", "\"TLS 1.0\"", "Violation"),
            ("ssh-protocol-conflict", "SSH", "protocol", "\"TLS\"", "Pass"),
            ("smb-protocol-conflict", "SMB", "protocol", "\"SSH\"", "Pass"),
            ("ldap-protocol-conflict", "LDAP", "protocol", "\"OpenVPN\"", "Pass"),
            ("ike-protocol-conflict", "IKEv2", "protocol", "\"WireGuard\"", "Pass"),
            ("wireguard-protocol-conflict", "WireGuard", "protocol", "\"IKEv2\"", "Pass"),
            ("openvpn-protocol-conflict", "OpenVPN", "protocol", "\"LDAP\"", "Pass"),
            ("smb-protocol-missing", "SMB", "protocol-missing", "", "Pass"),
            ("ssh-protocol-missing", "SSH", "protocol-missing", "", "Pass"),
            ("smb-protocol-violation", "SMB", "protocol-violation", "\"TLS\"", "Violation"),
            ("tls-protocol-conflict", "TLS", "protocol", "\"SMB\"", "Pass"),
            ("dtls-protocol-conflict", "DTLS", "protocol", "\"SSH\"", "Pass"),
            ("unknown-protocol-conflict", "Unknown", "protocol", "\"TLS\"", "Not applicable"),
            ("http-protocol-conflict", "HTTP", "protocol", "\"TLS\"", "Not applicable")
        })
        {
            var healthy = protocol switch
            {
                "SSH" => """
                    {"protocol":"SSH","ssh_selection":{"cipher_c2s":"aes256-gcm@openssh.com",
                    "cipher_s2c":"aes256-gcm@openssh.com"},"ssh_host_key_bits":256}
                    """,
                "SMB" => """
                    {"protocol":"SMB","smb_selected_cipher":["0x0002"],"smb_selected_signing_algorithm":["0x0002"],
                    "smb_selected_dialect":"0x0311","smb_server_signing_required":true,
                    "smb_signed_message_observed":true,"smb_encrypted_transform_observed":true}
                    """,
                "LDAP" => """{"protocol":"LDAP","ldap_session_protection":"Signed"}""",
                "IKEv2" => """{"protocol":"IKEv2","encryption":"AES-GCM-16","symmetric_key_bits":256}""",
                "WireGuard" => """
                    {"protocol":"WireGuard","encryption":"ChaCha20-Poly1305","symmetric_key_bits":256}
                    """,
                "TLS" or "DTLS" => "{\"protocol\":\"" + protocol + "\",\"group_class\":\"Classical\"}",
                "Unknown" or "HTTP" => "{\"protocol\":\"" + protocol + "\"}",
                _ => """
                    {"protocol":"OpenVPN","openvpn_tls_version":"TLS 1.3",
                    "openvpn_tls":{"selected_cipher":"TLS_AES_256_GCM_SHA384"}}
                    """
            };
            var damaged = protocol switch
            {
                "SSH" => field == "bits" ? healthy.Replace("\"ssh_host_key_bits\":256",
                    "\"ssh_host_key_bits\":" + value) : healthy.Replace("\"aes256-gcm@openssh.com\"", value),
                "SMB" => field switch
                {
                    "signing" => healthy.Replace("\"smb_server_signing_required\":true",
                        "\"smb_server_signing_required\":" + value),
                    "signed" => healthy.Replace("\"smb_signed_message_observed\":true",
                        "\"smb_signed_message_observed\":" + value),
                    "encrypted" => healthy.Replace("\"smb_encrypted_transform_observed\":true",
                        "\"smb_encrypted_transform_observed\":" + value),
                    "algorithm" => healthy.Replace("\"smb_selected_signing_algorithm\":[\"0x0002\"]",
                        "\"smb_selected_signing_algorithm\":" + value),
                    "dialect" => healthy.Replace("\"smb_selected_dialect\":\"0x0311\"",
                        "\"smb_selected_dialect\":" + value),
                    _ => healthy.Replace("\"smb_selected_cipher\":[\"0x0002\"]",
                        "\"smb_selected_cipher\":" + value)
                },
                "LDAP" => healthy.Replace("\"Signed\"", value),
                "OpenVPN" => healthy.Replace(field == "version" ? "\"TLS 1.3\"" :
                    "\"TLS_AES_256_GCM_SHA384\"", value),
                _ => field == "bits" ? healthy.Replace("\"symmetric_key_bits\":256",
                    "\"symmetric_key_bits\":" + value) :
                    healthy.Replace(protocol == "IKEv2" ? "\"AES-GCM-16\"" : "\"ChaCha20-Poly1305\"", value)
            };
            if (field is "protocol" or "protocol-missing" or "protocol-violation")
                damaged = field == "protocol-missing" ? healthy.Replace("\"protocol\":\"" + protocol + "\",", "") :
                    healthy.Replace("\"protocol\":\"" + protocol + "\"", "\"protocol\":" + value);
            if (field == "protocol-violation")
                damaged = damaged.Replace("\"smb_selected_cipher\":[\"0x0002\"]", "\"smb_selected_cipher\":[1]");
            command.Parameters.Clear();
            command.CommandText = """
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                UPDATE connections SET tls_name=@protocol,tls_version=@version,source_process='recovery-client',
                    sni=CASE WHEN id=(SELECT min(id) FROM connections) THEN 'damaged' ELSE 'healthy' END,
                    crypto_json=CASE WHEN id=(SELECT min(id) FROM connections) THEN @damaged ELSE @healthy END,
                    change_revision=(SELECT revision FROM metadata);
                """;
            command.Parameters.AddWithValue("@protocol", protocol switch
            {
                "SSH" => "SSH 2.0", "TLS" => "TLS 1.3", "DTLS" => "DTLS 1.2", _ => protocol
            });
            command.Parameters.AddWithValue("@version", protocol == "DTLS" ? 771 :
                protocol == "TLS" ? 772 : DBNull.Value);
            command.Parameters.AddWithValue("@damaged", damaged);
            command.Parameters.AddWithValue("@healthy", healthy);
            command.ExecuteNonQuery();
            if (source.Provider != DatabaseProvider.Sqlite)
                while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
            var policy = new CryptoPolicy { Name = "Recovery", Protocol = protocol switch
                {
                    "SSH" => PolicyProtocol.Ssh, "SMB" => PolicyProtocol.Smb, "LDAP" => PolicyProtocol.Ldap,
                    "IKEv2" => PolicyProtocol.IkeV2, "WireGuard" => PolicyProtocol.WireGuard,
                    "TLS" or "DTLS" or "Unknown" or "HTTP" => PolicyProtocol.Tls,
                    _ => PolicyProtocol.OpenVpn
                },
                AllowedSshCiphers = protocol == "SSH" ? "aes256-gcm@openssh.com" : "",
                MinimumSshHostKeyBits = field == "bits" ? 256 : 0,
                AllowedSmbCiphers = protocol == "SMB" ? "2" : "",
                AllowedSmbSigningAlgorithms = field == "algorithm" ? "2" : "",
                MinimumSmbDialect = field == "dialect" ? 0x0311 : 0,
                RequireSmbSigningRequired = field == "signing", RequireSmbSigning = field == "signed",
                RequireSmbEncryption = field == "encrypted", RequireLdapSaslProtection = protocol == "LDAP",
                AllowedVpnCiphers = protocol == "IKEv2" ? "AES-GCM-16" :
                    protocol == "WireGuard" ? "ChaCha20-Poly1305" : "",
                MinimumVpnKeyBits = protocol is "IKEv2" or "WireGuard" ? 256 : 0,
                AllowedOpenVpnControlCiphers = protocol == "OpenVPN" ? "TLS_AES_256_GCM_SHA384" : "",
                RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false };
            var checks = new List<object>();
            void Check(string operation, Func<bool> verify)
            {
                var passed = false;
                string? error = null;
                try { passed = verify(); }
                catch (Exception failure) { error = failure.ToString(); }
                checks.Add(new { operation, passed, error });
                if (!passed)
                    ++failures;
            }
            Check("policy-export", () =>
            {
                var file = Path.Combine(output, name + ".jsonl");
                var count = ReportExport.Write(source, query, ReportKind.Policies, file,
                    [policy], CancellationToken.None);
                if (expected == "Not applicable")
                    return count == 0;
                if (count != 2)
                    return false;
                var rows = File.ReadLines(file).Select(line =>
                {
                    using var row = JsonDocument.Parse(line);
                    return (Name: row.RootElement.GetProperty("server").GetString(),
                        Status: row.RootElement.GetProperty("status").GetString(),
                        Issues: row.RootElement.GetProperty("issues").EnumerateArray()
                            .Select(issue => issue.GetProperty("status").GetString()).ToHashSet());
                }).ToArray();
                var changed = rows.Single(row => row.Name == "damaged");
                return changed.Status == expected && (!name.EndsWith("partial-violation", StringComparison.Ordinal) ||
                    changed.Issues.SetEquals(["Violation", "Insufficient evidence"])) &&
                    rows.Single(row => row.Name == "healthy").Status == "Pass";
            });
            Check("policy-summary", () =>
            {
                var snapshot = PqcInsights.Read(source, query, 0, long.MaxValue,
                    "Client application", [policy], CancellationToken.None, includeReadiness: false);
                var summary = snapshot.Policies.Single();
                if (expected == "Not applicable")
                    return summary.Applicable == 0 && summary.Pass == 0 &&
                        summary.Insufficient == 0 && summary.Violations == 0;
                return summary.Applicable == 2 && summary.Pass == (expected == "Pass" ? 2 : 1) &&
                    summary.Insufficient == (expected == "Insufficient evidence" ? 1 : 0) &&
                    summary.Violations == (expected == "Violation" ? 1 : 0);
            });
            cases.Add(new { name, checks });
        }

        // A damaged timestamp must not hide an otherwise readable connection or its negotiation history.
        command.Parameters.Clear();
        command.CommandText = """
            UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
            UPDATE connections SET tls_name='TLS 1.3',sni='timestamp-damaged.test',ended_us=@last,
                crypto_json=@json,change_revision=(SELECT revision FROM metadata)
                WHERE id=(SELECT min(id) FROM connections);
            """;
        command.Parameters.AddWithValue("@last", long.MaxValue);
        command.Parameters.AddWithValue("@json", """
            {"protocol":"TLS","client_hello_us":-9223372036854775808,"server_hello_us":9223372036854775807,
            "retry_us":1700000000000000,"quic_paths":[{"first_us":-9223372036854775808,
            "last_us":9223372036854775807}],"negotiation_stages":[{"type":"ClientHello","ordinal":1,
            "timestamp_us":9223372036854775807}],"endpoint_confirmations":[{"timestamp_us":9223372036854775807}]}
            """);
        command.ExecuteNonQuery();
        if (source.Provider != DatabaseProvider.Sqlite)
            while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
        var timestampPassed = false;
        string? timestampError = null;
        try
        {
            var row = Database.Read(source, query, CancellationToken.None).Rows
                .Single(row => row.Sni == "timestamp-damaged.test");
            timestampPassed = row.Value("ClientHello") == "Invalid timestamp" &&
                row.Value("ServerHello") == "Invalid timestamp" && row.Value("Ended") == "Invalid timestamp" &&
                row.Value("RetryTime") is not ("Invalid timestamp" or "Not observed") &&
                row.Value("AlertTime") == "Not observed" &&
                row.Properties.Any(property => property.Category == "QUIC path 01" &&
                    property.Name == "First observed" && property.Value == "Invalid timestamp") &&
                row.Properties.Any(property => property.Category == "Negotiation 01 · ClientHello" &&
                    property.Name == "Observed" && property.Value == "Invalid timestamp") &&
                row.Properties.Any(property => property.Category == "Endpoint evidence 1" &&
                    property.Name == "Reported at" && property.Value == "Invalid timestamp");
        }
        catch (Exception failure) { timestampError = failure.ToString(); }
        cases.Add(new { name = "invalid-observation-timestamps", checks = new[]
            { new { operation = "connection-and-details", passed = timestampPassed, error = timestampError } } });
        if (!timestampPassed)
            ++failures;
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        { passed = failures == 0, provider = source.Provider.ToString(), cases },
            new JsonSerializerOptions { WriteIndented = true }));
        if (failures != 0)
            throw new InvalidOperationException($"{failures} protocol recovery checks failed.");
        Console.WriteLine($"Protocol recovery: {cases.Count} cases passed.");
    }
}
