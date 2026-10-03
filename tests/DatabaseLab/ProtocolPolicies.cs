using System.Text.Json;
using System.Xml.Linq;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class ProtocolPolicies
{
    public static void Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "protocol-policies.db");
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        {
            source.Open();
            connection.Open();
            source.BackupDatabase(connection);
        }
        var fixtures = new[]
        {
            ("SSH 2.0", "SSH", "ssh-good", """
                {"protocol":"SSH","ssh_selection":{"key_exchange":"curve25519-sha256","host_key":"ssh-ed25519",
                "cipher_c2s":"chacha20-poly1305@openssh.com","cipher_s2c":"aes256-gcm@openssh.com"},
                "ssh_host_key_bits":256,"ssh_host_key_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
                """),
            ("SSH 2.0", "SSH", "ssh-weak", """
                {"protocol":"SSH","ssh_selection":{"key_exchange":"diffie-hellman-group1-sha1","host_key":"ssh-rsa",
                "cipher_c2s":"aes128-cbc","cipher_s2c":"aes128-cbc","mac_c2s":"hmac-sha1","mac_s2c":"hmac-sha1"},
                "ssh_host_key_bits":1024,"ssh_host_key_sha256":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
                """),
            ("SSH 2.0", "SSH", "ssh-offers", """{"protocol":"SSH","ssh_peers":[{"kexinit_observed":true}]}"""),
            ("SMB", "SMB", "smb-good", """
                {"protocol":"SMB","smb_selected_dialect":"0x0311","smb_server_signing_required":true,
                "smb_selected_cipher":["0x0002"],"smb_selected_signing_algorithm":["0x0002"],
                "smb_signed_message_observed":true,"smb_encrypted_transform_observed":true}
                """),
            ("SMB", "SMB", "smb-capability", """
                {"protocol":"SMB","smb_selected_dialect":"0x0311","smb_server_signing_required":true,
                "smb_selected_cipher":["0x0002"],"smb_selected_signing_algorithm":["0x0002"],"smb_server_capabilities":64}
                """),
            ("SMB", "SMB", "smb-weak", """
                {"protocol":"SMB","smb_selected_dialect":"0x0202","smb_server_signing_required":false,
                "smb_selected_cipher":["0x0001"],"smb_selected_signing_algorithm":["0x0001"]}
                """),
            ("WireGuard", "WireGuard", "wireguard", """
                {"protocol":"WireGuard","encryption":"ChaCha20-Poly1305","key_exchange":"Curve25519",
                "symmetric_key_bits":256,"vpn_authentication":"Unverified"}
                """),
            ("IKEv2", "IKEv2", "ike-good", """
                {"protocol":"IKEv2","encryption":"AES-GCM-16","key_exchange":"Curve25519","symmetric_key_bits":256,
                "vpn_authentication":"Unverified"}
                """),
            ("IKEv2", "IKEv2", "ike-weak", """
                {"protocol":"IKEv2","encryption":"3DES","key_exchange":"MODP 1024","symmetric_key_bits":192,
                "vpn_authentication":"Unverified"}
                """),
            ("IKEv2", "IKEv2", "ike-offers", """{"protocol":"IKEv2","ike_offers":[],"vpn_authentication":"Unverified"}"""),
            ("OpenVPN", "OpenVPN", "openvpn-good", """
                {"protocol":"OpenVPN","openvpn_tls_version":"TLS 1.3",
                "openvpn_tls":{"selected_cipher":"TLS_AES_256_GCM_SHA384"},"vpn_authentication":"Unverified"}
                """),
            ("OpenVPN", "OpenVPN", "openvpn-weak", """
                {"protocol":"OpenVPN","openvpn_tls_version":"TLS 1.0",
                "openvpn_tls":{"selected_cipher":"TLS_RSA_WITH_AES_128_CBC_SHA"},"vpn_authentication":"Unverified"}
                """),
            ("OpenVPN", "OpenVPN", "openvpn-offers", """
                {"protocol":"OpenVPN","openvpn_tls_version":"Not selected","vpn_authentication":"Unverified"}
                """),
            ("TLS 1.2", "TLS", "tls", """{"protocol":"TLS","group_class":"Classical"}""")
        };

        // Retain the collector's schema and process/socket rows while varying realistic protocol outcomes.
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(connections)";
        var columns = new List<string>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                if (reader.GetString(1) != "id")
                    columns.Add(reader.GetString(1));
        command.CommandText = "DELETE FROM connection_certificates; DELETE FROM endpoint_certificates; " +
            "DELETE FROM endpoint_events; DELETE FROM connections WHERE id<>(SELECT min(id) FROM connections)";
        command.ExecuteNonQuery();
        command.CommandText = "WITH RECURSIVE copies(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM copies WHERE n<@count) " +
            "INSERT INTO connections(" + string.Join(',', columns) + ") SELECT " +
            string.Join(',', columns.Select(column => column == "flow_id" ? "c.flow_id+n" : "c." + column)) +
            " FROM (SELECT * FROM connections LIMIT 1) c CROSS JOIN copies";
        command.Parameters.AddWithValue("@count", fixtures.Length - 1);
        command.ExecuteNonQuery();
        command.CommandText = "SELECT id FROM connections ORDER BY id";
        var ids = new List<long>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                ids.Add(reader.GetInt64(0));
        for (var index = 0; index < fixtures.Length; index++)
        {
            var fixture = fixtures[index];
            command.Parameters.Clear();
            command.CommandText = """
                UPDATE connections SET sni=@name,tls_name=@protocol,tls_version=@version,crypto_json=@json,
                    first_us=@time,last_us=@time+1000,source_process='policy-client',source_path='C:/Lab/policy-client.exe',
                    destination_process='policy-server',destination_path='C:/Lab/policy-server.exe' WHERE id=@id
                """;
            command.Parameters.AddWithValue("@name", fixture.Item3);
            command.Parameters.AddWithValue("@protocol", fixture.Item1);
            command.Parameters.AddWithValue("@version", fixture.Item2 == "TLS" ? 771 : DBNull.Value);
            command.Parameters.AddWithValue("@json", fixture.Item4);
            command.Parameters.AddWithValue("@time", 1000000 + index * 1000000);
            command.Parameters.AddWithValue("@id", ids[index]);
            command.ExecuteNonQuery();
        }
        var policies = new[]
        {
            new CryptoPolicy { Name = "SSH", Protocol = PolicyProtocol.Ssh, AllowedSshKeyExchanges = "curve25519-sha256",
                AllowedSshHostKeys = "ssh-ed25519", AllowedSshCiphers = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
                AllowedSshMacs = "implicit-aead", MinimumSshHostKeyBits = 256,
                AllowedSshHostKeyFingerprints = new string('A', 64) },
            new CryptoPolicy { Name = "SMB", Protocol = PolicyProtocol.Smb, MinimumSmbDialect = 0x0311,
                RequireSmbSigningRequired = true, RequireSmbSigning = true, RequireSmbEncryption = true,
                AllowedSmbCiphers = "0x0002", AllowedSmbSigningAlgorithms = "2" },
            new CryptoPolicy { Name = "WireGuard", Protocol = PolicyProtocol.WireGuard,
                AllowedVpnCiphers = "ChaCha20-Poly1305", AllowedVpnKeyExchanges = "Curve25519", MinimumVpnKeyBits = 256 },
            new CryptoPolicy { Name = "VPN authentication", Protocol = PolicyProtocol.WireGuard, RequireVpnAuthentication = true },
            new CryptoPolicy { Name = "IKE", Protocol = PolicyProtocol.IkeV2, AllowedVpnCiphers = "AES-GCM-16",
                AllowedVpnKeyExchanges = "Curve25519", MinimumVpnKeyBits = 256 },
            new CryptoPolicy { Name = "OpenVPN control", Protocol = PolicyProtocol.OpenVpn,
                AllowedOpenVpnControlCiphers = "TLS_AES_256_GCM_SHA384" },
            new CryptoPolicy { Name = "OpenVPN data", Protocol = PolicyProtocol.OpenVpn,
                AllowedVpnCiphers = "AES-256-GCM", RequireVpnAuthentication = true },
            new CryptoPolicy { Name = "TLS", RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false }
        };
        var policyFile = Path.Combine(output, "protocol-policies.config");
        new XDocument(new XElement("cipherazzi", new XElement("viewer", new XAttribute("analyticsMinutes", 0)),
            new XElement("policies", policies.Select(policy => policy.ToXml())))).Save(policyFile);
        var sourceDatabase = DatabaseSource.Sqlite(path);
        var evaluator = PolicyEvaluator.Load(policyFile);
        var results = new Dictionary<string, List<PolicyResult>>();
        command.Parameters.Clear();
        command.CommandText = """
            SELECT c.*,c.id AS policy_observation_id,c.ech_offered AS policy_ech_offered,c.tls_name AS policy_protocol,
                '' AS policy_certificate_facts,c.crypto_json AS metadata_json,s.computer_name AS computer
            FROM connections c JOIN capture_sessions s ON s.id=c.run_id
            """;
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                results.Add(reader.GetString(reader.GetOrdinal("sni")), evaluator.Evaluate(
                    PolicyEvaluator.ConnectionEvidence(reader, reader.GetString(reader.GetOrdinal("computer")))));
        var checks = new List<string>();
        void Check(bool condition, string text)
        {
            if (!condition)
                throw new InvalidOperationException(text);
            checks.Add(text);
        }
        foreach (var (name, status) in new[]
        {
            ("ssh-good", "Pass"), ("ssh-weak", "Violation"), ("ssh-offers", "Insufficient evidence"),
            ("smb-good", "Pass"), ("smb-capability", "Insufficient evidence"), ("smb-weak", "Violation"),
            ("ike-good", "Pass"), ("ike-weak", "Violation"), ("ike-offers", "Insufficient evidence"),
            ("openvpn-good", "Pass"), ("openvpn-weak", "Violation"), ("openvpn-offers", "Insufficient evidence"), ("tls", "Pass")
        })
            Check(results[name][0].Status == status, name + " retains its observed policy outcome");
        Check(results["wireguard"][0].Status == "Pass" && results["wireguard"][1].Status == "Insufficient evidence",
            "WireGuard's fixed algorithms do not establish tunnel authentication");
        Check(results["openvpn-good"][1].Status == "Insufficient evidence",
            "OpenVPN control TLS does not establish the data-channel cipher or VPN authentication");
        var query = new Query("", "", false, PageCursor.Newest);
        var snapshot = PqcInsights.Read(sourceDatabase, query, 0, long.MaxValue, "Client application",
            policies, CancellationToken.None);
        Check(snapshot.Total == 1 && snapshot.PolicyObservations == fixtures.Length,
            "Protocol policies evaluate all applicable observations without changing TLS readiness denominators");
        Check(snapshot.Policies.Single(policy => policy.Name == "SSH") is { Pass: 1, Violations: 1, Insufficient: 1 } &&
            snapshot.Policies.Single(policy => policy.Name == "SMB") is { Pass: 1, Violations: 1, Insufficient: 1 },
            "Viewer policy summaries preserve every protocol result");
        var scoped = policies[0].Clone();
        scoped.ProcessRole = PolicyEndpoint.Server;
        scoped.Process = "policy-client";
        Check(PqcInsights.Read(sourceDatabase, query, 0, long.MaxValue, "Client application", [scoped],
            CancellationToken.None).Policies.Single().Applicable == 0, "SSH scope respects the selected process role");
        Check(PqcInsights.Read(sourceDatabase, query with { Protocol = "SMB" }, 0, long.MaxValue, "Client application",
            policies, CancellationToken.None).PolicyObservations == 3, "Protocol filters apply to non-TLS policy evaluation");
        Check(PqcInsights.Read(sourceDatabase, query, 4000000, 5000000, "Client application", policies,
            CancellationToken.None).PolicyObservations == 2, "Time boundaries apply to protocol policy observations");
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new { checks, results },
            new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Protocol policies: {checks.Count} checks passed.");
    }
}
