using System.Data.Common;
using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;

internal static class EndpointFeatures
{
    public static void RunBrowser(string[] args)
    {
        var directory = Path.GetFullPath(args[0]);
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        using var fixtures = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "results.json")));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        var results = new List<object>();
        foreach (var fixture in fixtures.RootElement.GetProperty("cases").EnumerateArray())
        {
            var name = fixture.GetProperty("case").GetString()!;
            var success = fixture.GetProperty("success").GetBoolean();
            var version = fixture.GetProperty("tls_version").GetInt32();
            var source = DatabaseSource.Sqlite(Path.Combine(directory, name, "endpoints.db"));
            using var connection = source.CreateConnection();
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT detail_json FROM endpoint_events";
            var detail = (string)command.ExecuteScalar()!;
            var flow = PolicyEvaluator.EndpointEvidence(detail, "Browser lab", "1")!;
            Check(flow.Tls == version && flow.Transport == fixture.GetProperty("transport").GetString(),
                "Browser evidence changed its reported version or transport.");
            Check(flow.ClientProcess.Length == 0 && flow.ServerProcess.Length == 0 && flow.EndpointProcess.Length > 0,
                "Application identity was assigned a socket process role.");
            Check(flow.Completion == (success ? "Completed" : "Failed"),
                "Public browser completion did not survive assessment projection.");

            // Assess the actual imported reports through the shared evaluator and readiness query.
            var policies = new[]
            {
                new CryptoPolicy { Name = "TLS 1.3", MinimumTls = 772, RequirePostQuantumKeyExchange = false,
                    RequireEndpointCompletion = false },
                new CryptoPolicy { Name = "Completed TLS", MinimumTls = 771, RequirePostQuantumKeyExchange = false },
                new CryptoPolicy { Name = "Verified peer", MinimumTls = 771, RequirePostQuantumKeyExchange = false,
                    RequireEndpointCompletion = false, RequirePeerVerification = true },
                new CryptoPolicy { Name = "Handshake signature", MinimumTls = 771,
                    RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false,
                    AllowedServerSignatures = "0x0804" },
                new CryptoPolicy { Name = "PQ authentication", MinimumTls = 771,
                    RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false,
                    RequirePostQuantumServerAuthentication = true }
            };
            var evaluated = new PolicyEvaluator(policies).Evaluate(flow).ToDictionary(result => result.Name);
            var protocolFailure = !success && version == 0;
            Check(evaluated["TLS 1.3"].Status == (version == 771 ? "Violation" :
                protocolFailure ? "Insufficient evidence" : "Pass"),
                "QUIC's minimum or the browser's actual TLS selection was assessed incorrectly.");
            Check(evaluated["Completed TLS"].Status == (success ? "Pass" : "Violation"),
                "A rejected browser handshake was reported as complete.");
            Check(evaluated["Verified peer"].Status == (success ? "Pass" :
                protocolFailure ? "Insufficient evidence" : "Violation"),
                "Peer verification did not retain the browser's public decision.");
            Check(evaluated["Handshake signature"].Status == "Insufficient evidence" &&
                evaluated["PQ authentication"].Status == "Insufficient evidence",
                "A certificate signature was substituted for the unobserved handshake signature.");
            var snapshot = PqcInsights.Read(source, new Query("", "", false, PageCursor.Newest),
                0, long.MaxValue, "Client application", policies, deadline.Token);
            Check(snapshot.Total == 1 && snapshot.Rows.Sum(row => row.Complete) == (success ? 1 : 0) &&
                snapshot.Rows.Sum(row => row.Failures) == (success ? 0 : 1),
                "Browser readiness omitted or duplicated an endpoint-only result.");
            Check(snapshot.Policies.All(policy => policy.Applicable == 1),
                "Application-scoped browser evidence did not reach applicable policies.");
            results.Add(new { name, exact_tls_version = flow.Tls, flow.Transport,
                policies = evaluated.Values.Select(result => new { result.Name, result.Status }) });
        }
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        {
            cases = results, exact_version_preserved = true, unknown_handshake_authentication_preserved = true,
            application_role_preserved = true, readiness_and_policy_projection = true
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Browser evidence and policy checks passed for {results.Count} actual imported exchanges.");
    }

    public static async Task RunAsync(string[] args)
    {
        var path = Path.GetFullPath(args[0]);
        var local = DatabaseSource.Sqlite(path);
        var directory = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(directory);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var targets = new List<DatabaseSource> { local };
        var results = new List<object>();
        try
        {
            foreach (var (provider, variable) in new[] { ("sqlserver", "CIPHERAZZI_SQLSERVER"),
                ("postgresql", "CIPHERAZZI_POSTGRESQL") })
            {
                if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(variable)))
                    continue;
                var target = PqcConnectivity.FreshTarget(DatabaseSource.FromEnvironment(provider, variable));
                targets.Add(target);
                if (args.Length > 2)
                {
                    var configuration = Path.Combine(directory, provider + ".json");
                    var credentialFile = Path.Combine(directory, provider + ".credential");
                    ConnectionCredentials.Save(credentialFile, target);
                    File.WriteAllText(configuration, JsonSerializer.Serialize(new Dictionary<string, object>
                    {
                        ["source"] = Path.GetRelativePath(directory, path), ["provider"] = provider,
                        ["connection-file"] = Path.GetFileName(credentialFile)
                    }));
                    var start = new ProcessStartInfo(Path.GetFullPath(args[2]))
                    {
                        UseShellExecute = false, CreateNoWindow = true,
                        RedirectStandardOutput = true, RedirectStandardError = true
                    };
                    start.ArgumentList.Add("--config");
                    start.ArgumentList.Add(configuration);
                    start.ArgumentList.Add("--once");
                    using var process = Process.Start(start)!;
                    var output = process.StandardOutput.ReadToEndAsync();
                    var error = process.StandardError.ReadToEndAsync();
                    await process.WaitForExitAsync(deadline.Token);
                    await output;
                    Check(process.ExitCode == 0, "Configured relay failed: " + await error);
                }
                await Replication.InitializeAsync(target, deadline.Token);
                while ((await Replication.SyncAsync(path, target, deadline.Token)).More) {}
            }
            foreach (var target in targets)
            {
                PqcSnapshot Read(Query? query = null, CryptoPolicy? policy = null) => PqcInsights.Read(target,
                    query ?? new Query("", "", false, PageCursor.Newest), 0, long.MaxValue, "Client application",
                    [policy ?? new CryptoPolicy()], deadline.Token);
                var snapshot = Read();
                Check(snapshot.Total == 13, "Associated reports were counted twice or unmatched reports were omitted.");
                Check(snapshot.Rows.Sum(row => row.Count("Evidence source", "Endpoint")) == 9,
                    "Endpoint provenance is missing from readiness.");
                Check(snapshot.Rows.Sum(row => row.Complete) == 8,
                    "Endpoint completion did not contribute to readiness.");
                Check(snapshot.Rows.Sum(row => row.Count("Peer verification", "Verified")) == 6,
                    "Provider success was treated as peer verification.");
                Check(snapshot.Policies[0].Examples.Any(example => example.EndpointEventId.Length > 0),
                    "Policy findings did not retain the endpoint event identity.");
                Check(snapshot.Rows.Sum(row => row.Count("Presented server-chain signatures", "Post-quantum")) == 7,
                    "Reported certificate algorithms did not reach readiness.");
                var dtls = Read(new Query("", "DTLS 1.2", false, PageCursor.Newest));
                Check(dtls.Total == 1 && dtls.Rows.Sum(row => row.Count("Completion", "Conflicting")) == 1,
                    "DTLS completion or protocol filtering failed.");
                var loopback = Read(new Query("127.0.0.1", "", false, PageCursor.Newest));
                Check(loopback.Total == 1 && loopback.Rows.Sum(row => row.Complete) == 1,
                    "Endpoint-only loopback evidence was excluded from readiness.");
                var client = Read(policy: new CryptoPolicy
                    { Process = "java.exe", ProcessRole = PolicyEndpoint.Client });
                var server = Read(policy: new CryptoPolicy
                    { Process = "java.exe", ProcessRole = PolicyEndpoint.Server });
                Check(client.Policies[0].Applicable == 9 && server.Policies[0].Applicable == 0,
                    "Unknown provider roles were assigned to a client or server policy.");
                results.Add(new { provider = target.Provider.ToString(), observations = snapshot.Total,
                    completed = snapshot.Rows.Sum(row => row.Complete), endpoint_only = 9 });
            }
        }
        finally
        {
            foreach (var target in targets.Skip(1))
                await RemoveAsync(target);
        }
        File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(results,
            new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(JsonSerializer.Serialize(results));
    }

    private static async Task RemoveAsync(DatabaseSource target)
    {
        var builder = target.Provider == DatabaseProvider.SqlServer ?
            (DbConnectionStringBuilder)new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(
                target.ConnectionString) :
            new Npgsql.NpgsqlConnectionStringBuilder(target.ConnectionString);
        var key = target.Provider == DatabaseProvider.SqlServer ? "Initial Catalog" : "Database";
        var name = builder[key].ToString()!;
        if (!name.StartsWith("CipherazziPqc_", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected test database name.");
        builder[key] = target.Provider == DatabaseProvider.SqlServer ? "master" : "postgres";
        using var connection = new DatabaseSource(target.Provider, builder.ConnectionString).CreateConnection();
        await connection.OpenAsync();
        using var command = connection.CreateCommand();
        command.CommandText = target.Provider == DatabaseProvider.SqlServer ?
            $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]" :
            $"DROP DATABASE \"{name}\" WITH (FORCE)";
        await command.ExecuteNonQueryAsync();
    }

    private static void Check(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
