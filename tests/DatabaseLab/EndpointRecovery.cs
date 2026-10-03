using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

internal static class EndpointRecovery
{
    public static void Scale(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var existing = args.Contains("--existing");
        var path = existing ? Path.GetFullPath(args[0]) : Path.Combine(output, "endpoint-scale.db");
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        connection.Open();
        if (!existing)
        {
            using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
            {
                original.Open();
                original.BackupDatabase(connection);
            }
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT run_id,flow_id,first_us FROM connections ORDER BY id LIMIT 1";
            string run;
            long flow, first;
            using (var reader = command.ExecuteReader())
            {
                reader.Read();
                run = reader.GetString(0);
                flow = reader.GetInt64(1);
                first = reader.GetInt64(2);
            }
            var detail = JsonSerializer.Serialize(new
            {
                matched_run_id = run,
                assessment = new { first_us = first, last_us = first + 1000, tls_version = 772,
                    local_role = "Unknown", process = "scale.exe", path = "C:/scale.exe", server_name = "scale.test",
                    server_port = 443, group_name = "X25519", key_exchange = "ECDHE", authentication = "",
                    certificate_facts = "", crypto = new { protocol = "TLS", evidence_source = "Endpoint" } }
            });
            command.CommandText = """
                DELETE FROM endpoint_certificates;
                DELETE FROM endpoint_events;
                WITH RECURSIVE rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM rows WHERE n<100000)
                INSERT INTO endpoint_events(id,run_id,timestamp_us,provider,kind,result,pid,peer,port,protocol,cipher,
                    certificate_id,detail_json,change_revision)
                SELECT 'scale-'||n,@run,@first+n,'Scale adapter','TLS','Reported completion',1234,'scale.test',443,
                    'TLS 1.3','','',json_set(@detail,
                        '$.matched_flow_id',CASE WHEN n%2=0 THEN @flow ELSE @missing END,
                        '$.assessment.first_us',@first+n*2000,'$.assessment.last_us',@first+n*2000+1000,
                        '$.assessment.local_role',CASE n%3 WHEN 0 THEN 'Client' WHEN 1 THEN 'Server' ELSE 'Unknown' END,
                        '$.assessment.process','scale-'||(n%3)||'.exe',
                        '$.assessment.path','C:/scale-'||(n%3)||'.exe',
                        '$.assessment.server_name','cohort-'||(n%7)||'.test',
                        '$.assessment.crypto.selected_group_id',CASE n%5 WHEN 0 THEN 4588 ELSE 29 END,
                        '$.assessment.crypto.group_class',CASE n%5 WHEN 0 THEN 'Hybrid post-quantum'
                            WHEN 1 THEN 'Classical' ELSE 'Not observed' END,
                        '$.assessment.crypto.group_standardization','Standardized',
                        '$.assessment.crypto.classification_rule_version','Scale rules',
                        '$.diagnostic','Report '||n||' at '||(@first+n*2000)),1
                    FROM rows;
                """;
            command.Parameters.AddWithValue("@run", run);
            command.Parameters.AddWithValue("@first", first);
            command.Parameters.AddWithValue("@flow", flow);
            command.Parameters.AddWithValue("@missing", long.MaxValue);
            command.Parameters.AddWithValue("@detail", detail);
            command.ExecuteNonQuery();
            command.Parameters.Clear();
        }
        using var measure = connection.CreateCommand();
        var source = DatabaseSource.Sqlite(path);
        var results = new List<object>();
        if (!args.Contains("--readiness-only"))
        {
            foreach (var (name, match) in new[]
            {
                ("numeric-cast", "c.run_id=json_extract(e.detail_json,'$.matched_run_id') AND " +
                    "c.flow_id=CAST(json_extract(e.detail_json,'$.matched_flow_id') AS BIGINT)"),
                ("typed-association", PolicyEvaluator.EndpointMatchSql(source, "e.detail_json", "c"))
            })
            {
                measure.CommandText = "SELECT count(*) FROM endpoint_events e WHERE NOT EXISTS " +
                    "(SELECT 1 FROM connections c WHERE " + match + ")";
                var watch = Stopwatch.StartNew();
                var count = (long)measure.ExecuteScalar()!;
                if (count != 50000)
                    throw new InvalidOperationException("Association scaling lost independent endpoint evidence.");
                results.Add(new { name, count, elapsed_ms = watch.Elapsed.TotalMilliseconds });
            }
        }

        // Measure narrow scopes against the same large journal used for complete readiness reads.
        int? clientPort = null;
        var portOption = Array.IndexOf(args, "--client-port");
        if (portOption >= 0)
        {
            if (portOption + 1 >= args.Length || !int.TryParse(args[portOption + 1], NumberStyles.None,
                CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
                throw new ArgumentException("Choose a client port between 1 and 65535.");
            clientPort = port;
        }
        var query = new Query("", "", false, PageCursor.Newest);
        if (clientPort is { } selectedPort)
            query = query with { Conditions = [new(ObservationField.ClientPort, FilterComparison.Equals,
                selectedPort.ToString(CultureInfo.InvariantCulture))] };
        var repetitions = 1;
        var repeatOption = Array.IndexOf(args, "--repeat");
        if (repeatOption >= 0 && (repeatOption + 1 >= args.Length ||
            !int.TryParse(args[repeatOption + 1], NumberStyles.None, CultureInfo.InvariantCulture, out repetitions) ||
                repetitions is < 1 or > 20))
            throw new ArgumentException("Choose between 1 and 20 readiness measurements.");
        var samples = new List<double>();
        var hashes = new List<string>();
        PqcSnapshot snapshot = null!;
        var snapshotJson = "";
        for (var iteration = 0; iteration < repetitions; ++iteration)
        {
            var assessmentWatch = Stopwatch.StartNew();
            snapshot = PqcInsights.Read(source, query, 0, long.MaxValue,
                "Client application", [new(), new() { Name = "Client scope", ProcessRole = PolicyEndpoint.Client,
                    Process = "scale-0.exe" }, new() { Name = "Peer scope", ServerName = "cohort-1.test" }],
                CancellationToken.None);
            samples.Add(assessmentWatch.Elapsed.TotalMilliseconds);
            snapshotJson = JsonSerializer.Serialize(snapshot);
            hashes.Add(Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(snapshotJson))));
        }
        measure.CommandText = "SELECT COUNT(*) FROM endpoint_events";
        var endpoints = (long)measure.ExecuteScalar()!;
        var assessmentMs = samples[^1];
        File.WriteAllText(Path.Combine(output, "snapshot.json"), snapshotJson);
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        { endpoint_rows = endpoints, client_port = clientPort, measurements = results, readiness_ms = assessmentMs,
            readiness_samples_ms = samples, readiness_observations = snapshot.Total,
            snapshot_sha256 = hashes[^1], snapshot_samples_sha256 = hashes },
            new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(JsonSerializer.Serialize(results));
        Console.WriteLine($"Readiness: {snapshot.Total} observations in {assessmentMs:F1} ms.");
    }

    public static async Task RunAsync(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "endpoints.db");
        using (var input = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            input.Open();
            copy.Open();
            input.BackupDatabase(copy);
        }
        using var writer = new SqliteConnection($"Data Source={path};Pooling=False");
        writer.Open();
        using var command = writer.CreateCommand();
        command.CommandText = """
            PRAGMA foreign_keys=OFF;
            DELETE FROM endpoint_certificates;
            DELETE FROM endpoint_events;
            DELETE FROM connection_certificates;
            DELETE FROM connections WHERE id<>(SELECT min(id) FROM connections);
            UPDATE connections SET flow_id=1,source_process='packet-client.exe',source_path='C:/packet-client.exe',
                destination_process='packet-server.exe',destination_path='C:/packet-server.exe';
            SELECT run_id,first_us,(SELECT min(sha256) FROM certificates) FROM connections;
            """;
        string run, hash;
        long first;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read() || reader.IsDBNull(2))
                throw new InvalidOperationException("Endpoint recovery requires a connection and public certificate.");
            run = reader.GetString(0);
            first = reader.GetInt64(1);
            hash = reader.GetString(2);
        }
        command.CommandText = "SELECT sha256,metadata_json,der FROM certificates WHERE sha256<>@hash LIMIT 1";
        command.Parameters.AddWithValue("@hash", hash);
        string spareHash, spareMetadata;
        byte[] spareDer;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read())
                throw new InvalidOperationException("Endpoint recovery requires two public certificates.");
            spareHash = reader.GetString(0);
            spareMetadata = reader.GetString(1);
            spareDer = reader.GetFieldValue<byte[]>(2);
        }
        command.Parameters.Clear();
        var observed = first + 10000;
        command.CommandText = """
            DELETE FROM certificates WHERE sha256<>@hash;
            UPDATE connections SET certificate_sha256=@hash;
            INSERT INTO connection_certificates(run_id,flow_id,role,chain_index,sha256,change_revision)
                VALUES(@run,1,'server',0,@hash,1);
            INSERT INTO endpoint_events(id,run_id,timestamp_us,provider,kind,result,pid,peer,port,protocol,cipher,
                certificate_id,detail_json,change_revision)
                VALUES('endpoint-recovery',@run,@time,'Recovery adapter','TLS','Reported completion',1234,
                    'endpoint-only.test',443,'TLS 1.3','TLS_AES_128_GCM_SHA256',@hash,'{}',1);
            INSERT INTO endpoint_certificates(event_id,sha256) VALUES('endpoint-recovery',@hash);
            """;
        command.Parameters.AddWithValue("@run", run);
        command.Parameters.AddWithValue("@time", observed);
        command.Parameters.AddWithValue("@hash", hash);
        command.ExecuteNonQuery();
        var source = args.Length > 2 ? DatabaseSource.FromEnvironment(args[2], "CIPHERAZZI_CONNECTION") :
            DatabaseSource.Sqlite(path);
        if (source.Provider != DatabaseProvider.Sqlite)
        {
            var name = source.Provider == DatabaseProvider.SqlServer ?
                new SqlConnectionStringBuilder(source.ConnectionString).InitialCatalog :
                new NpgsqlConnectionStringBuilder(source.ConnectionString).Database;
            if (name?.StartsWith("CipherazziEndpoint_", StringComparison.Ordinal) != true)
                throw new InvalidOperationException("Use an isolated CipherazziEndpoint_ database.");
            await Replication.InitializeAsync(source, CancellationToken.None);
        }
        var template = new JsonObject
        {
            ["matched_run_id"] = run,
            ["matched_flow_id"] = 1,
            ["assessment"] = new JsonObject
            {
                ["first_us"] = first, ["last_us"] = first + 1000, ["tls_version"] = 772,
                ["local_role"] = "Unknown", ["process"] = "endpoint-only.exe", ["path"] = "C:/endpoint-only.exe",
                ["server_name"] = "endpoint-only.test", ["server_port"] = 443, ["group_name"] = "X25519",
                ["key_exchange"] = "ECDHE", ["authentication"] = "", ["certificate_facts"] = "",
                ["crypto"] = new JsonObject { ["protocol"] = "TLS", ["transport"] = "TCP",
                    ["evidence_source"] = "Endpoint", ["group_class"] = "Classical" }
            }
        };
        var results = new List<object>();
        var failures = 0;
        var query = new Query("", "", false, PageCursor.Newest);
        foreach (var (name, value, matched, missing) in new (string, string, bool, string?)[]
        {
            ("integer", "1", true, null), ("null", "null", false, null),
            ("string-integer", "\"1\"", false, null), ("string-prefix", "\"1garbage\"", false, null),
            ("boolean", "true", false, null), ("fraction", "1.5", false, null),
            ("decimal-integer", "1.0", false, null), ("exponent", "1e0", false, null),
            ("overflow", "9223372036854775808", false, null),
            ("duplicate", "1", false, null), ("missing-first", "null", false, "first_us"),
            ("missing-version", "null", false, "tls_version"), ("missing-crypto", "null", false, "crypto"),
            ("malformed-json", "null", false, "$malformed"), ("array-root", "null", false, "$array"),
            ("negative-first", "null", false, "$negative-first"),
            ("reversed-times", "null", false, "$reversed-times"),
            ("string-first", "null", false, "$string-first"),
            ("overflow-first", "null", false, "$overflow-first"),
            ("missing-last", "null", false, "last_us"),
            ("late-first-without-last", "null", false, "$late-first"),
            ("early-last-without-first", "null", false, "$early-last"),
            ("protocol-conflict", "null", false, null), ("protocol-missing", "null", false, null),
            ("protocol-dtls", "null", false, null), ("protocol-raw", "null", false, null),
            ("flow-key-space", "1", false, null), ("run-key-space", "1", false, null),
            ("flow-key-neighbor", "1", true, null), ("run-key-neighbor", "1", true, null)
        })
        {
            // A damaged link must remain independent, and incomplete assessments retain explicit unknown evidence.
            var detail = (JsonObject)template.DeepClone();
            detail["matched_flow_id"] = JsonNode.Parse(value);
            if (name.EndsWith("-key-space") || name.EndsWith("-key-neighbor"))
            {
                var key = name.StartsWith("flow") ? "matched_flow_id" : "matched_run_id";
                detail[key + " "] = detail[key]!.DeepClone();
                if (name.EndsWith("-key-space"))
                    detail.Remove(key);
            }
            if (missing is not null && !missing.StartsWith('$'))
                detail["assessment"]!.AsObject().Remove(missing);
            if (missing == "$negative-first") detail["assessment"]!["first_us"] = -1;
            if (missing == "$reversed-times") detail["assessment"]!["last_us"] = first - 1;
            if (missing == "$string-first") detail["assessment"]!["first_us"] = "invalid";
            if (missing == "$overflow-first")
                detail["assessment"]!["first_us"] = JsonNode.Parse("9223372036854775808");
            if (missing == "$late-first")
            {
                detail["assessment"]!["first_us"] = observed + 3000;
                detail["assessment"]!.AsObject().Remove("last_us");
            }
            if (missing == "$early-last")
            {
                detail["assessment"]!.AsObject().Remove("first_us");
                detail["assessment"]!["last_us"] = first - 1000;
            }
            if (name.StartsWith("protocol-", StringComparison.Ordinal))
            {
                var crypto = detail["assessment"]!["crypto"]!.AsObject();
                if (name == "protocol-missing")
                    crypto.Remove("protocol");
                else
                    crypto["protocol"] = name == "protocol-raw" ? "TLS" : "SSH";
                if (name == "protocol-dtls")
                    crypto["transport"] = "DTLS";
            }
            var json = detail.ToJsonString();
            if (missing == "$malformed") json = "{\"assessment\":";
            if (missing == "$array") json = "[]";
            if (name == "duplicate")
                json = json.Replace("\"matched_flow_id\":1", "\"matched_flow_id\":1,\"matched_flow_id\":1");
            command.Parameters.Clear();
            command.CommandText = """
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                UPDATE endpoint_events SET detail_json=@detail,protocol=@protocol,
                    change_revision=(SELECT revision FROM metadata);
                """;
            command.Parameters.AddWithValue("@detail", json);
            command.Parameters.AddWithValue("@protocol", name == "protocol-dtls" ? "DTLS 1.3" :
                name == "protocol-raw" ? "Raw cryptography" : "TLS 1.3");
            command.ExecuteNonQuery();
            if (source.Provider != DatabaseProvider.Sqlite)
                while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
            var checks = new List<object>();
            void Check(string operation, Func<bool> action)
            {
                bool passed;
                string? error = null;
                try { passed = action(); }
                catch (Exception failure) { passed = false; error = failure.ToString(); }
                checks.Add(new { operation, passed, error });
                if (!passed)
                    ++failures;
            }
            var expected = matched || name == "protocol-raw" || missing is "$malformed" or "$array" ? 1 : 2;
            Check("readiness", () => PqcInsights.Read(source, query, 0, long.MaxValue,
                "Client application", [new()], CancellationToken.None).Total == expected);
            Check("policy-export", () => ReportExport.Write(source, query, ReportKind.Policies,
                Path.Combine(output, name + ".jsonl"), [new()], CancellationToken.None) == expected);
            if (name.StartsWith("protocol-", StringComparison.Ordinal))
                Check("protocol-identity", () =>
                {
                    var protocols = File.ReadLines(Path.Combine(output, name + ".jsonl")).Select(line =>
                    {
                        using var document = JsonDocument.Parse(line);
                        return (Endpoint: document.RootElement.GetProperty("endpoint_event_id").GetString(),
                            Protocol: document.RootElement.GetProperty("protocol").GetString());
                    }).Where(row => row.Endpoint?.Length > 0).ToArray();
                    return name == "protocol-raw" ? protocols.Length == 0 :
                        protocols.Single().Protocol == (name == "protocol-dtls" ? "DTLS" : "TLS");
                });
            Check("certificate-ownership", () =>
            {
                var use = CertificateInventory.ReadUses(source, hash, CancellationToken.None)
                    .Single(use => use.Evidence == "Endpoint");
                return use.ClientApplication == (matched ? "C:/packet-client.exe" : "") &&
                    use.FirstUs >= 0 && use.LastUs >= use.FirstUs;
            });
            if (missing is not null and not "last_us" and not "$late-first")
                Check("assessment-decoder", () => PolicyEvaluator.EndpointEvidence(json, "Recovery", "event") is
                    { EvidenceError.Length: > 0, ClientPath.Length: 0, ServerPath.Length: 0 });
            if (missing is "$reversed-times" or "$late-first" or "$early-last")
                Check("certificate-interval", () =>
                {
                    var use = CertificateInventory.ReadUses(source, hash, CancellationToken.None)
                        .Single(use => use.Evidence == "Endpoint");
                    var certificate = CertificateInventory.Read(source, "", "All certificates", "",
                        CancellationToken.None).Rows.Single(row => row.Sha256 == hash);
                    return use.FirstUs == observed && use.LastUs == observed &&
                        certificate.FirstUs == first && certificate.LastUs == observed;
                });
            if (missing is "$malformed" or "$array")
            {
                Check("endpoint-search", () => Insights.ReadEvents(source, query with { Search = "absent" },
                    long.MaxValue, "\uffff", 0, CancellationToken.None).Rows.Count == 0);
                Check("endpoint-filter", () =>
                {
                    var rows = Insights.ReadEvents(source, query with
                    {
                        Conditions = [new(ObservationField.Process, FilterComparison.NotObserved)]
                    }, long.MaxValue, "\uffff", 0, CancellationToken.None).Rows;
                    return rows.Count == 1 && rows[0].Provider == "Recovery adapter" &&
                        rows[0].Properties.Any(property => property.Category == "Endpoint evidence" &&
                            property.Value == "Recorded endpoint metadata could not be read");
                });
            }
            results.Add(new { name, expected_associated = matched, checks });
        }

        // Invalid packet documents remain one unknown assessment, including roots that are valid non-object JSON.
        command.Parameters.Clear();
        command.CommandText = "SELECT crypto_json,tls_name,tls_version FROM connections";
        string originalCrypto, originalProtocol;
        int? originalVersion;
        using (var reader = command.ExecuteReader())
        {
            reader.Read();
            originalCrypto = reader.GetString(0);
            originalProtocol = reader.GetString(1);
            originalVersion = reader.IsDBNull(2) ? null : reader.GetInt32(2);
        }
        var versionPolicy = new CryptoPolicy
        { RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false };
        foreach (var (name, crypto, unknown) in new[]
        {
            ("packet-malformed", "invalid JSON", true), ("packet-array", "[{\"transport\":\"TCP\"}]", true),
            ("packet-scalar", "true", true), ("packet-spaced-object", "\r\n\t {}", false)
        })
        {
            command.Parameters.Clear();
            command.CommandText = """
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                UPDATE connections SET crypto_json=@crypto,change_revision=(SELECT revision FROM metadata);
                UPDATE endpoint_events SET detail_json=@detail,change_revision=(SELECT revision FROM metadata);
                """;
            command.Parameters.AddWithValue("@crypto", crypto);
            command.Parameters.AddWithValue("@detail", template.ToJsonString());
            command.ExecuteNonQuery();
            if (source.Provider != DatabaseProvider.Sqlite)
                while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
            var passed = false;
            string? error = null;
            try
            {
                var snapshot = PqcInsights.Read(source, query, 0, long.MaxValue, "Client application",
                    [versionPolicy], CancellationToken.None);
                File.WriteAllText(Path.Combine(output, name + "-readiness.json"), JsonSerializer.Serialize(snapshot));
                var policy = snapshot.Policies.Single();
                passed = snapshot.Total == 1 && policy.Applicable == 1 && policy.Violations == 0 &&
                    policy.Insufficient == (unknown ? 1 : 0) && policy.Pass == (unknown ? 0 : 1) &&
                    (!unknown || policy.Examples.Single().Reasons.Contains("could not be read",
                        StringComparison.Ordinal));
            }
            catch (Exception failure) { error = failure.ToString(); }
            results.Add(new { name, checks = new[] { new { operation = "packet-readiness", passed, error } } });
            if (!passed)
                ++failures;
        }
        // A late malformed report cannot retain signatures or protocol selections from a partial decode.
        var report = new { local_role = "Client", success = true, peer_verified = 1,
            handshake_signature_id = 0x0804, local_handshake_signature_id = 0x0805,
            authentication_class = "Classical", local_authentication_class = "Classical" };
        var validReport = JsonSerializer.Serialize(report);
        string Reports(string malformed) => "[" + validReport + "," + malformed + "]";
        string Crypto(string confirmations, string protocol = "TLS") =>
            "{\"protocol\":\"" + protocol + "\",\"endpoint_confirmations\":" + confirmations +
            ",\"ssh_selection\":{\"cipher_c2s\":\"aes128-cbc\",\"cipher_s2c\":\"aes128-cbc\"}}";
        string UnknownSignature(string value) => "[{\"local_role\":\"Client\",\"success\":true," +
            "\"handshake_signature_id\":" + value + ",\"local_handshake_signature_id\":" + value + "}]";
        foreach (var (name, protocol, crypto, unreadable, signatures) in new[]
        {
            ("packet-late-null-report", "TLS", Crypto(Reports("null")), true, true),
            ("packet-missing-report-outcome", "TLS", Crypto(Reports("{\"local_role\":\"Server\"}")), true, true),
            ("packet-invalid-report-outcome", "TLS", Crypto(Reports("{\"success\":\"unknown\"}")), true, true),
            ("packet-numeric-report-outcome", "TLS", Crypto(Reports("{\"success\":2}")), true, true),
            ("packet-ssh-partial-evidence", "SSH", Crypto(Reports("null"), "SSH"), true, true),
            ("packet-reports-object", "TLS", Crypto(validReport), true, false),
            ("packet-reports-string", "TLS", Crypto("\"[]\""), true, false),
            ("packet-reports-empty-string", "TLS", Crypto("\"\""), true, false),
            ("packet-reports-number", "TLS", Crypto("1"), true, false),
            ("packet-reports-boolean", "TLS", Crypto("true"), true, false),
            ("packet-array-report", "TLS", Crypto(Reports("[\"Client\",true,1,2052,\"Classical\"," +
                "2053,\"Classical\",\"\"]")), true, true),
            ("packet-compact-root", "TLS", "[null,null,null,null,null,null,null,null,null,null,[]]", true, false),
            ("packet-signature-text", "TLS", Crypto(UnknownSignature("\"not-an-id\"")), false, true),
            ("packet-signature-fraction", "TLS", Crypto(UnknownSignature("2052.5")), false, true),
            ("packet-signature-overflow", "TLS", Crypto(UnknownSignature("2147483648")), false, true),
            ("packet-signature-container", "TLS", Crypto(UnknownSignature("[2052]")), false, true),
            ("packet-role-unknown", "TLS", Crypto("[" + validReport.Replace("\"Client\"", "\"Unknown\"") + "]"),
                false, true),
            ("packet-role-missing", "TLS", Crypto("[" + validReport.Replace("\"local_role\":\"Client\",", "") + "]"),
                false, true),
            ("packet-reports-null", "TLS", Crypto("null"), false, false),
            ("packet-reports-empty", "TLS", Crypto("[]"), false, false),
            ("packet-reports-spaced-array", "TLS", Crypto("\r\n\t []"), false, false)
        })
        {
            command.Parameters.Clear();
            command.CommandText = """
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                UPDATE connections SET crypto_json=@crypto,tls_name=@protocol,tls_version=@version,
                    change_revision=(SELECT revision FROM metadata);
                """;
            command.Parameters.AddWithValue("@crypto", crypto);
            command.Parameters.AddWithValue("@protocol", protocol == "SSH" ? "SSH 2.0" : "TLS 1.3");
            command.Parameters.AddWithValue("@version", protocol == "SSH" ? DBNull.Value : (object)772);
            command.ExecuteNonQuery();
            if (source.Provider != DatabaseProvider.Sqlite)
                while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
            var policy = new CryptoPolicy { RequirePostQuantumKeyExchange = false,
                RequireStandardizedPqGroup = false, RequireEndpointCompletion = false,
                Protocol = protocol == "SSH" ? PolicyProtocol.Ssh : PolicyProtocol.Tls,
                AllowedServerSignatures = signatures ? "0x0904" : "",
                AllowedClientSignatures = signatures ? "0x0905" : "",
                AllowedSshCiphers = "chacha20-poly1305@openssh.com" };
            var expectedStatus = unreadable || signatures ? "Insufficient evidence" : "Pass";
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
            Check("partial-packet-decoder", () =>
            {
                using var input = source.OpenConnectionAsync(CancellationToken.None).GetAwaiter().GetResult();
                using var read = input.CreateCommand();
                read.CommandText = $"""
                    SELECT c.*,c.id AS policy_observation_id,c.ech_offered AS policy_ech_offered,
                        c.tls_name AS policy_protocol,'' AS policy_certificate_facts,c.crypto_json AS metadata_json
                    FROM {source.Prefix}connections c
                    """;
                using var row = read.ExecuteReader();
                row.Read();
                var flow = PolicyEvaluator.ConnectionEvidence(row, "Recovery");
                var assessment = new PolicyEvaluator([policy]).Evaluate(flow).Single();
                File.WriteAllText(Path.Combine(output, name + "-decoded.json"), JsonSerializer.Serialize(new
                {
                    flow.EvidenceError, flow.ServerSignatureIds, flow.ClientSignatureIds,
                    flow.Completion, flow.PeerVerification, assessment.Status
                }));
                return (flow.EvidenceError.Length > 0) == unreadable && flow.Protocol == protocol &&
                    flow.ServerSignatureIds.Count == 0 && flow.ClientSignatureIds.Count == 0 &&
                    flow.ClientProcess == "packet-client.exe" && flow.Computer == "Recovery" &&
                    assessment.Status == expectedStatus;
            });
            Check("partial-packet-export", () =>
            {
                var file = Path.Combine(output, name + ".jsonl");
                if (ReportExport.Write(source, query, ReportKind.Policies, file,
                    [policy], CancellationToken.None) != 1)
                    return false;
                using var row = JsonDocument.Parse(File.ReadAllText(file));
                return row.RootElement.GetProperty("status").GetString() == expectedStatus;
            });
            Check("partial-packet-readiness", () =>
            {
                var snapshot = PqcInsights.Read(source, query, 0, long.MaxValue,
                    "Client application", [policy], CancellationToken.None);
                File.WriteAllText(Path.Combine(output, name + "-readiness.json"), JsonSerializer.Serialize(snapshot));
                var summary = snapshot.Policies.Single();
                return summary.Applicable == 1 && summary.Insufficient == (unreadable || signatures ? 1 : 0) &&
                    summary.Pass == (unreadable || signatures ? 0 : 1) && summary.Violations == 0;
            });
            results.Add(new { name, checks });
        }
        command.Parameters.Clear();
        command.CommandText = """
            UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
            UPDATE connections SET crypto_json=@crypto,tls_name=@protocol,tls_version=@version,
                change_revision=(SELECT revision FROM metadata);
            """;
        command.Parameters.AddWithValue("@crypto", originalCrypto);
        command.Parameters.AddWithValue("@protocol", originalProtocol);
        command.Parameters.AddWithValue("@version", originalVersion is { } version ? version : DBNull.Value);
        command.ExecuteNonQuery();
        if (source.Provider != DatabaseProvider.Sqlite)
            while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }

        // The collector's expression index must supply the profile without reparsing the complete document.
        if (source.Provider == DatabaseProvider.Sqlite)
        {
            command.Parameters.Clear();
            command.CommandText = "SELECT 1 FROM sqlite_schema WHERE name='connections_readiness'";
            if (command.ExecuteScalar() is not null)
            {
                var projection = (string)typeof(PqcInsights).GetMethod("CryptoProfile",
                    System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!
                    .Invoke(null, [source])!;
                command.CommandText = "EXPLAIN SELECT " + projection +
                    " FROM connections c INDEXED BY connections_readiness";
                var functions = new List<string>();
                using (var reader = command.ExecuteReader())
                    while (reader.Read())
                        if (reader.GetString(1) is "Function" or "PureFunc" && !reader.IsDBNull(5))
                            functions.Add(reader.GetString(5));
                var cached = !functions.Contains("json_valid(1)", StringComparer.OrdinalIgnoreCase);
                results.Add(new { name = "readiness-index", checks = new[]
                    { new { operation = "cached-profile", passed = cached, functions } } });
                if (!cached)
                    ++failures;
            }
        }

        // Damaged catalog metadata must not hide a certificate, its original bytes, or unrelated policy evidence.
        command.Parameters.Clear();
        command.CommandText = "SELECT metadata_json,der FROM certificates WHERE sha256=@hash";
        command.Parameters.AddWithValue("@hash", hash);
        string originalMetadata;
        byte[] originalDer;
        using (var reader = command.ExecuteReader())
        {
            reader.Read();
            originalMetadata = reader.GetString(0);
            originalDer = reader.GetFieldValue<byte[]>(1);
        }
        var certificate = JsonNode.Parse(originalMetadata)!.AsObject();
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
        const long day = 24L * 60 * 60 * 1000000;
        certificate["not_before_us"] = now - 2 * day;
        certificate["not_after_us"] = now - day;
        string Metadata(string value, string field = "not_after_us")
        {
            var changed = certificate.DeepClone();
            changed[field] = JsonNode.Parse(value);
            return changed.ToJsonString();
        }
        var expiredMetadata = certificate.ToJsonString();
        var expiry = JsonSerializer.Serialize(now - day);
        var historic = (JsonObject)certificate.DeepClone();
        historic["not_before_us"] = -315619201000000L;
        historic["not_after_us"] = -315619200000000L;
        var largeCertificate = (JsonObject)certificate.DeepClone();
        largeCertificate["padding"] = new string('x', 65537);
        var certificatePolicy = new CryptoPolicy
        {
            RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false,
            AllowedCertificateKeys = certificate["public_key_oid"]!.GetValue<string>()
        };
        foreach (var (name, json, expires, notice, knownKey) in new (string, string, long?, bool, bool)[]
        {
            ("certificate-expired", expiredMetadata, now - day, false, true),
            ("certificate-soon", Metadata(JsonSerializer.Serialize(now + 7 * day)), now + 7 * day, false, true),
            ("certificate-historic", historic.ToJsonString(), -315619200000000L, false, true),
            ("certificate-large-metadata", largeCertificate.ToJsonString(), now - day, false, true),
            ("certificate-large-facts", Metadata(JsonSerializer.Serialize("1.2.3." + new string('1', 65537)),
                "signature_oid"), now - day, false, true),
            ("certificate-malformed", "{invalid", null, true, false),
            ("certificate-array", "[]", null, true, false),
            ("certificate-scalar", "true", null, true, false),
            ("certificate-oversize", JsonSerializer.Serialize(new { padding = new string('x', 2 * 1024 * 1024) }),
                null, true, false),
            ("certificate-deep", "{\"padding\":" + new string('[', 36) + "0" + new string(']', 36) + "}",
                null, true, false),
            ("certificate-empty", "{}", null, false, false),
            ("certificate-string-date", Metadata("\"0\""), null, true, true),
            ("certificate-fraction-date", Metadata("1.5"), null, true, true),
            ("certificate-overflow-date", Metadata("9223372036854775808"), null, true, true),
            ("certificate-range-date", Metadata("253402300800000000"), null, true, true),
            ("certificate-boolean-date", Metadata("true"), null, true, true),
            ("certificate-reversed-dates", Metadata(JsonSerializer.Serialize(now - 3 * day)), null, true, true),
            ("certificate-duplicate-date", expiredMetadata.Replace("\"not_after_us\":" + expiry,
                "\"not_after_us\":" + expiry + ",\"not_after_us\":" + expiry), null, true, true),
            ("certificate-space-date", expiredMetadata.Replace("\"not_after_us\":" + expiry,
                "\"not_after_us \":" + expiry), null, false, true),
            ("certificate-neighbor-date", expiredMetadata.Replace("\"not_after_us\":" + expiry,
                "\"not_after_us\":" + expiry + ",\"not_after_us \":" + expiry), now - day, false, true),
            ("certificate-array-key", Metadata("[]", "public_key_oid"), now - day, false, false),
            ("certificate-space-key", expiredMetadata.Replace("\"public_key_oid\":",
                "\"public_key_oid \":"), now - day, false, false),
            ("certificate-neighbor-key", expiredMetadata.Replace("\"public_key_oid\":",
                "\"public_key_oid \":\"1.2.3\",\"public_key_oid\":"), now - day, false, true),
            ("certificate-duplicate-key", expiredMetadata.Replace("\"public_key_oid\":",
                "\"public_key_oid\":\"1.2.3\",\"public_key_oid\":"), now - day, false, false)
        })
        {
            command.Parameters.Clear();
            command.CommandText = """
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                UPDATE certificates SET metadata_json=@json,change_revision=(SELECT revision FROM metadata)
                    WHERE sha256=@hash;
                """;
            command.Parameters.AddWithValue("@json", json);
            command.Parameters.AddWithValue("@hash", hash);
            command.ExecuteNonQuery();
            if (source.Provider != DatabaseProvider.Sqlite)
                while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
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
            Check("certificate-inventory", () =>
            {
                var row = CertificateInventory.Read(source, "", "All certificates", "", CancellationToken.None)
                    .Rows.Single(row => row.Sha256 == hash);
                return row.NotAfterUs == expires && row.Observations == 1 &&
                    (!notice || row.Properties.Any(property => property.Name == "Metadata")) &&
                    CertificateInventory.ReadDer(source, hash, CancellationToken.None).SequenceEqual(originalDer);
            });
            Check("certificate-connection-details", () =>
            {
                var properties = Insights.ReadCertificates(source, ["server|" + hash, "client|" + hash],
                    CancellationToken.None);
                return new[] { "server certificate", "client certificate" }.All(category =>
                    properties.Any(property => property.Category == category && property.Name == "SHA-256" &&
                        property.Value == hash) && (!notice || properties.Any(property =>
                        property.Category == category && property.Name == "Metadata")));
            });
            Check("certificate-expiry-filters", () =>
                CertificateInventory.Read(source, "", "Expired", "", CancellationToken.None).Rows.Count ==
                    (expires < now ? 1 : 0) && CertificateInventory.Read(source, "", "Expires within 30 days", "",
                        CancellationToken.None).Rows.Count == (expires >= now && expires <= now + 30 * day ? 1 : 0));
            Check("certificate-readiness", () =>
            {
                var policy = PqcInsights.Read(source, query, 0, long.MaxValue, "Client application",
                    [certificatePolicy], CancellationToken.None).Policies.Single();
                return policy.Applicable == 1 && policy.Violations == 0 &&
                    policy.Pass == (knownKey ? 1 : 0) && policy.Insufficient == (knownKey ? 0 : 1);
            });
            Check("certificate-policy-export", () =>
            {
                var report = Path.Combine(output, name + ".jsonl");
                if (ReportExport.Write(source, query, ReportKind.Policies, report,
                    [certificatePolicy], CancellationToken.None) != 1)
                    return false;
                using var row = JsonDocument.Parse(File.ReadAllText(report));
                return row.RootElement.GetProperty("status").GetString() ==
                    (knownKey ? "Pass" : "Insufficient evidence");
            });
            results.Add(new { name, checks });
        }
        command.Parameters.Clear();
        command.CommandText = """
            UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
            UPDATE certificates SET metadata_json=@json,change_revision=(SELECT revision FROM metadata)
                WHERE sha256=@hash;
            """;
        command.Parameters.AddWithValue("@json", originalMetadata);
        command.Parameters.AddWithValue("@hash", hash);
        command.ExecuteNonQuery();
        if (source.Provider != DatabaseProvider.Sqlite)
            while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }

        // Distinct real certificates exercise entry eviction without losing or mixing algorithm assessments.
        command.Parameters.Clear();
        command.CommandText = "SELECT * FROM connections WHERE flow_id=1";
        var cacheValues = new Dictionary<string, object?>();
        using (var reader = command.ExecuteReader())
        {
            reader.Read();
            for (var index = 0; index < reader.FieldCount; ++index)
                cacheValues[reader.GetName(index)] = reader.IsDBNull(index) ? null : reader.GetValue(index);
        }
        cacheValues.Remove("id");
        cacheValues["sni"] = "cache-count.test";
        cacheValues["crypto_json"] = "{\"transport\":\"TCP\"}";
        cacheValues["tls_name"] = "TLS 1.3";
        cacheValues["tls_version"] = 772;
        const string ecOid = "1.2.840.10045.2.1";
        var cacheCertificates = new List<(string Hash, int Flow, JsonObject Metadata)>();
        using var cacheEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var cacheRsa = RSA.Create(2048);
        using (var transaction = writer.BeginTransaction())
        {
            command.Transaction = transaction;
            command.CommandText = "UPDATE metadata SET revision=revision+1,observation_revision=revision+1;" +
                "SELECT revision FROM metadata";
            var revision = (long)command.ExecuteScalar()!;
            cacheValues["change_revision"] = revision;
            var insert = "INSERT INTO connections(" + string.Join(',', cacheValues.Keys) + ") VALUES(" +
                string.Join(',', cacheValues.Keys.Select((_, index) => "@value" + index)) + ")";
            var created = DateTimeOffset.UtcNow;
            for (var index = 0; index < 300; ++index)
            {
                var ec = index % 2 == 0;
                var request = ec ? new CertificateRequest("CN=Cache " + index, cacheEc, HashAlgorithmName.SHA256) :
                    new CertificateRequest("CN=Cache " + index, cacheRsa, HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);
                using var generated = request.CreateSelfSigned(created.AddDays(-1), created.AddDays(1));
                var der = generated.RawData;
                var fingerprint = Convert.ToHexStringLower(SHA256.HashData(der));
                var metadata = new JsonObject
                {
                    ["public_key_oid"] = ec ? ecOid : "1.2.840.113549.1.1.1",
                    ["signature_oid"] = ec ? "1.2.840.10045.4.3.2" : "1.2.840.113549.1.1.11",
                    ["public_key_class"] = "Classical", ["certificate_signature_class"] = "Classical",
                    ["cache_index"] = index
                };
                var flow = 20000000 + index;
                cacheCertificates.Add((fingerprint, flow, metadata));
                command.Parameters.Clear();
                command.CommandText = "INSERT INTO certificates(sha256,metadata_json,der,change_revision) " +
                    "VALUES(@hash,@metadata,@der,@revision)";
                command.Parameters.AddWithValue("@hash", fingerprint);
                command.Parameters.AddWithValue("@metadata", metadata.ToJsonString());
                command.Parameters.AddWithValue("@der", der);
                command.Parameters.AddWithValue("@revision", revision);
                command.ExecuteNonQuery();
                cacheValues["flow_id"] = flow;
                cacheValues["certificate_sha256"] = fingerprint;
                command.CommandText = insert;
                command.Parameters.Clear();
                var parameter = 0;
                foreach (var value in cacheValues.Values)
                    command.Parameters.AddWithValue("@value" + parameter++, value ?? DBNull.Value);
                command.ExecuteNonQuery();
                command.CommandText = "INSERT INTO connection_certificates " +
                    "VALUES(@run,@flow,'server',0,@hash,@revision)";
                command.Parameters.Clear();
                command.Parameters.AddWithValue("@run", run);
                command.Parameters.AddWithValue("@flow", flow);
                command.Parameters.AddWithValue("@hash", fingerprint);
                command.Parameters.AddWithValue("@revision", revision);
                command.ExecuteNonQuery();
            }
            transaction.Commit();
            command.Transaction = null;
        }
        var cachePolicy = new CryptoPolicy { RequirePostQuantumKeyExchange = false,
            RequireStandardizedPqGroup = false, RequireEndpointCompletion = false, AllowedCertificateKeys = ecOid };
        foreach (var budget in new[] { false, true })
        {
            // Large facts and repeated certificate roles must retain complete assessments after byte eviction.
            var total = budget ? 24 : 300;
            var name = budget ? "certificate-cache-budget" : "certificate-cache-count";
            var peer = budget ? "cache-budget.test" : "cache-count.test";
            if (budget)
                using (var transaction = writer.BeginTransaction())
                {
                    command.Transaction = transaction;
                    command.Parameters.Clear();
                    command.CommandText = "UPDATE metadata SET revision=revision+1,observation_revision=revision+1";
                    command.ExecuteNonQuery();
                    foreach (var item in cacheCertificates.Take(total))
                    {
                        item.Metadata["padding"] = new string('x', 60000);
                        item.Metadata["signature_oid"] = "1.2.3." + new string('1', 60000);
                        item.Metadata["certificate_signature_class"] = "Unknown";
                        command.CommandText = """
                            UPDATE certificates SET metadata_json=@metadata,
                                change_revision=(SELECT revision FROM metadata) WHERE sha256=@hash;
                            UPDATE connections SET sni=@peer,change_revision=(SELECT revision FROM metadata)
                                WHERE run_id=@run AND flow_id=@flow;
                            INSERT OR IGNORE INTO connection_certificates
                                VALUES(@run,@flow,'client',0,@hash,(SELECT revision FROM metadata));
                            """;
                        command.Parameters.Clear();
                        command.Parameters.AddWithValue("@metadata", item.Metadata.ToJsonString());
                        command.Parameters.AddWithValue("@hash", item.Hash);
                        command.Parameters.AddWithValue("@run", run);
                        command.Parameters.AddWithValue("@flow", item.Flow);
                        command.Parameters.AddWithValue("@peer", peer);
                        command.ExecuteNonQuery();
                    }
                    transaction.Commit();
                    command.Transaction = null;
                }
            if (source.Provider != DatabaseProvider.Sqlite)
                while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
            var scoped = query with { Search = peer };
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
            Check("cache-readiness", () =>
            {
                var snapshot = PqcInsights.Read(source, scoped, 0, long.MaxValue, "Client application",
                    [cachePolicy], CancellationToken.None);
                var policy = snapshot.Policies.Single();
                return snapshot.Total == total && policy.Applicable == total && policy.Pass == total / 2 &&
                    policy.Violations == total / 2 && policy.Insufficient == 0;
            });
            Check("cache-policy-export", () =>
            {
                var report = Path.Combine(output, name + ".jsonl");
                if (ReportExport.Write(source, scoped, ReportKind.Policies, report,
                    [cachePolicy], CancellationToken.None) != total)
                    return false;
                var statuses = File.ReadLines(report).Select(line =>
                {
                    using var row = JsonDocument.Parse(line);
                    return row.RootElement.GetProperty("status").GetString();
                }).ToArray();
                return statuses.Count(status => status == "Pass") == total / 2 &&
                    statuses.Count(status => status == "Violation") == total / 2;
            });
            results.Add(new { name, connections = total, checks });
        }

        // A link's certificate can be newer than the bounded relay batch containing its endpoint parent.
        if (source.Provider != DatabaseProvider.Sqlite)
        {
            command.Parameters.Clear();
            command.CommandText = "SELECT * FROM capture_sessions WHERE id=@run";
            command.Parameters.AddWithValue("@run", run);
            var session = new Dictionary<string, object>();
            using (var reader = command.ExecuteReader())
            {
                reader.Read();
                for (var index = 0; index < reader.FieldCount; ++index)
                    session[reader.GetName(index)] = reader.GetValue(index);
            }
            command.Parameters.Clear();
            command.CommandText = "SELECT revision FROM metadata";
            var after = (long)command.ExecuteScalar()!;
            using (var transaction = writer.BeginTransaction())
            {
                command.Transaction = transaction;
                command.CommandText = """
                    UPDATE metadata SET revision=revision+6,observation_revision=revision+6;
                    INSERT INTO certificates(sha256,metadata_json,der,change_revision)
                        VALUES(@hash,@metadata,@der,@last);
                    UPDATE endpoint_events SET detail_json=@detail,change_revision=@first;
                    INSERT INTO endpoint_certificates(event_id,sha256) VALUES('endpoint-recovery',@hash);
                    """;
                command.Parameters.AddWithValue("@hash", spareHash);
                command.Parameters.AddWithValue("@metadata", spareMetadata);
                command.Parameters.AddWithValue("@der", spareDer);
                command.Parameters.AddWithValue("@first", after + 1);
                command.Parameters.AddWithValue("@last", after + 6);
                command.Parameters.AddWithValue("@detail", template.ToJsonString());
                command.ExecuteNonQuery();
                foreach (var offset in new[] { 2, 3, 4 })
                {
                    session["id"] = "closure-" + Guid.NewGuid().ToString("N");
                    session["change_revision"] = after + offset;
                    command.Parameters.Clear();
                    var parameters = session.Keys.Select((_, index) => "@value" + index).ToArray();
                    command.CommandText = "INSERT INTO capture_sessions(" + string.Join(',', session.Keys) +
                        ") VALUES(" + string.Join(',', parameters) + ")";
                    var index = 0;
                    foreach (var value in session.Values)
                        command.Parameters.AddWithValue(parameters[index++], value);
                    command.ExecuteNonQuery();
                }
                transaction.Commit();
                command.Transaction = null;
            }
            var batch = await Replication.SyncAsync(path, source, CancellationToken.None);
            var linked = batch.More && batch.Revision == after + 4 &&
                CertificateInventory.ReadDer(source, spareHash, CancellationToken.None).SequenceEqual(spareDer) &&
                CertificateInventory.ReadUses(source, spareHash, CancellationToken.None)
                    .Any(use => use.Evidence == "Endpoint");
            results.Add(new { name = "certificate-dependency-closure", passed = linked,
                batch.Revision, expected_boundary = after + 4 });
            if (!linked)
                ++failures;
            while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
        }
        // Certificate details retain healthy siblings and original DER beside an unreadable catalog document.
        command.Parameters.Clear();
        command.CommandText = """
            UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
            INSERT OR IGNORE INTO certificates(sha256,metadata_json,der,change_revision)
                VALUES(@spare,@metadata,@der,(SELECT revision FROM metadata));
            UPDATE certificates SET metadata_json='{invalid',change_revision=(SELECT revision FROM metadata)
                WHERE sha256=@hash;
            """;
        command.Parameters.AddWithValue("@spare", spareHash);
        command.Parameters.AddWithValue("@metadata", spareMetadata);
        command.Parameters.AddWithValue("@der", spareDer);
        command.Parameters.AddWithValue("@hash", hash);
        command.ExecuteNonQuery();
        if (source.Provider != DatabaseProvider.Sqlite)
            while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
        var isolation = false;
        string? isolationError = null;
        try
        {
            var properties = Insights.ReadCertificates(source,
                ["server|" + hash, "client|" + spareHash, "server|missing"], CancellationToken.None);
            using var healthy = JsonDocument.Parse(spareMetadata);
            isolation = properties.Where(property => property.Name == "SHA-256").Select(property => property.Value)
                .SequenceEqual(new[] { hash, spareHash }) &&
                properties.Any(property => property.Category == "server certificate" && property.Name == "Metadata") &&
                properties.Any(property => property.Category == "client certificate" && property.Name == "Subject" &&
                    property.Value == healthy.RootElement.GetProperty("subject").GetString()) &&
                CertificateInventory.ReadDer(source, hash, CancellationToken.None).SequenceEqual(originalDer);
        }
        catch (Exception error) { isolationError = error.ToString(); }
        results.Add(new { name = "certificate-details-isolation", checks = new[]
            { new { operation = "healthy-siblings-and-der", passed = isolation, error = isolationError } } });
        if (!isolation)
            ++failures;
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        { passed = failures == 0, provider = source.Provider.ToString(), cases = results },
            new JsonSerializerOptions { WriteIndented = true }));
        if (failures != 0)
            throw new InvalidOperationException($"{failures} endpoint recovery checks failed.");
        Console.WriteLine($"Endpoint recovery: {results.Count} cases passed for {source.Provider}.");
    }
}
