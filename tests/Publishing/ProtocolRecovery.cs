using System.Text.Json;
using System.Xml.Linq;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class ProtocolRecovery
{
    public static async Task VerifyAsync(string publisher, string seed, string output,
        Func<string, string[], Task<(int Exit, string Text)>> run, Action<bool, string> check)
    {
        foreach (var (name, protocol, damaged, expected) in new[]
        {
            ("ssh-unicode", "SSH", """
                {"protocol":"SSH","ssh_selection":{"cipher_c2s":"\ud800","cipher_s2c":"aes256-gcm@openssh.com"}}
                """, "Insufficient evidence"),
            ("smb-null", "SMB", """{"protocol":"SMB","smb_selected_cipher":[null]}""", "Insufficient evidence"),
            ("smb-partial", "SMB", """{"protocol":"SMB","smb_selected_cipher":[1,null]}""", "Violation"),
            ("smb-signing", "SMB", """
                {"protocol":"SMB","smb_selected_cipher":[2],"smb_signed_message_observed":"True"}
                """, "Insufficient evidence"),
            ("smb-protocol", "SMB", """{"protocol":"TLS","smb_selected_cipher":[1]}""", "Violation"),
            ("ssh-protocol-missing", "SSH", """
                {"ssh_selection":{"cipher_c2s":"aes128-cbc","cipher_s2c":"aes128-cbc"}}
                """, "Violation"),
            ("smb-protocol-unknown", "SMB", """{"protocol":"Unknown","smb_selected_cipher":[2]}""", "Pass")
        })
        {
            var path = Path.Combine(output, name + ".db");
            using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
            using (var original = new SqliteConnection($"Data Source={seed};Mode=ReadOnly;Pooling=False"))
            {
                original.Open();
                connection.Open();
                original.BackupDatabase(connection);
            }
            using var command = connection.CreateCommand();

            // Put the damaged observation before enough healthy observations to cross journal batch boundaries.
            var healthy = protocol == "SSH" ? """
                {"protocol":"SSH","ssh_selection":{"cipher_c2s":"aes256-gcm@openssh.com",
                "cipher_s2c":"aes256-gcm@openssh.com"}}
                """ : """{"protocol":"SMB","smb_selected_cipher":[2],"smb_signed_message_observed":true}""";
            command.CommandText = """
                DELETE FROM endpoint_certificates;
                DELETE FROM endpoint_events;
                DELETE FROM connection_certificates;
                DROP TABLE IF EXISTS publishing_cursors;
                DROP TABLE IF EXISTS replication_consumers;
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                UPDATE connections SET tls_name=@protocol,tls_version=NULL,
                    sni=CASE WHEN id=(SELECT min(id) FROM connections) THEN 'damaged' ELSE 'healthy' END,
                    crypto_json=CASE WHEN id=(SELECT min(id) FROM connections) THEN @damaged ELSE @healthy END,
                    change_revision=(SELECT revision FROM metadata);
                """;
            command.Parameters.AddWithValue("@protocol", protocol == "SSH" ? "SSH 2.0" : protocol);
            command.Parameters.AddWithValue("@damaged", damaged);
            command.Parameters.AddWithValue("@healthy", healthy);
            command.ExecuteNonQuery();
            long Scalar(string sql)
            {
                using var read = connection.CreateCommand();
                read.CommandText = sql;
                return Convert.ToInt64(read.ExecuteScalar());
            }
            var count = Scalar("SELECT count(*) FROM connections");
            var policy = new CryptoPolicy
            {
                Name = "Protocol recovery", Protocol = protocol == "SSH" ? PolicyProtocol.Ssh : PolicyProtocol.Smb,
                AllowedSshCiphers = protocol == "SSH" ? "aes256-gcm@openssh.com" : "",
                AllowedSmbCiphers = protocol == "SMB" ? "2" : "", RequireSmbSigning = name == "smb-signing"
            };
            var policyFile = Path.Combine(output, name + ".config");
            new XDocument(new XElement("cipherazzi", new XElement("policies", policy.ToXml()))).Save(policyFile);
            await using var receiver = new Receiver(null);
            string[] arguments = ["--source", path, "--syslog", $"tcp://localhost:{receiver.Port}",
                "--allow-plaintext-syslog", "--events", "policies", "--policies", policyFile, "--once"];
            var published = await run(publisher, arguments);
            await receiver.Until(() => receiver.Messages.Count >= count || published.Exit != 0);
            var payloads = receiver.Messages.Select(Receiver.Envelope)
                .Select(value => value.GetProperty("payload")).ToArray();
            var changed = payloads.SingleOrDefault(value => value.GetProperty("server").GetString() == "damaged");
            check(published.Exit == 0 && count > 256 && payloads.Length == count &&
                changed.ValueKind == JsonValueKind.Object && changed.GetProperty("status").GetString() == expected &&
                (name != "smb-partial" || changed.GetProperty("issues").EnumerateArray()
                    .Select(issue => issue.GetProperty("status").GetString()).ToHashSet()
                    .SetEquals(["Violation", "Insufficient evidence"])) &&
                payloads.Count(value => value.GetProperty("status").GetString() == "Pass") ==
                    (expected == "Pass" ? count : count - 1) &&
                Scalar("SELECT count(*) FROM publishing_cursors WHERE kind=4 " +
                    "AND revision=(SELECT revision FROM metadata)") == 1 &&
                Scalar("SELECT min(acknowledged_revision) FROM replication_consumers") ==
                    Scalar("SELECT revision FROM metadata"),
                name + ": damaged evidence preserves healthy delivery and advances the durable cursor");

            // A restart must not repeat the batch; corrected evidence must publish one later passing assessment.
            var resumed = await run(publisher, arguments);
            check(resumed.Exit == 0 && receiver.Messages.Count == count,
                name + ": restarting resumes after the completed protocol assessments");
            command.CommandText = """
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                UPDATE connections SET crypto_json=@healthy,change_revision=(SELECT revision FROM metadata)
                    WHERE id=(SELECT min(id) FROM connections);
                """;
            command.ExecuteNonQuery();
            var recovered = await run(publisher, arguments);
            await receiver.Until(() => receiver.Messages.Count >= count + 1 || recovered.Exit != 0);
            check(recovered.Exit == 0 && receiver.Messages.Count == count + 1 &&
                Receiver.Envelope(receiver.Messages.Last()).GetProperty("payload").GetProperty("status")
                    .GetString() == "Pass" &&
                Scalar("SELECT min(acknowledged_revision) FROM replication_consumers") ==
                    Scalar("SELECT revision FROM metadata"),
                name + ": corrected evidence publishes recovery without replaying healthy observations");
        }
    }
}
