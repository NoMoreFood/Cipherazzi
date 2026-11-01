using System.Data.Common;
using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class EndpointFeatures
{
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
                if (args.Contains("--local") || string.IsNullOrEmpty(Environment.GetEnvironmentVariable(variable)))
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
                        ["source"] = Path.GetRelativePath(directory, path),
                        ["provider"] = provider,
                        ["connection-file"] = Path.GetFileName(credentialFile)
                    }));
                    var start = new ProcessStartInfo(Path.GetFullPath(args[2]))
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
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
                while ((await Replication.SyncAsync(path, target, deadline.Token)).More) { }
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
                var inventory = CertificateInventory.Read(target, "", "All certificates", "", deadline.Token);
                Check(inventory.Rows.Count == 2 && inventory.Rows.All(row => row.Observations == 7 &&
                    row.Computers == 1 && row.Applications == 1 && row.FirstUs is not null),
                    "Certificate inventory omitted endpoint-only evidence or counted matched reports twice.");
                Check(CertificateInventory.Read(target, "java.exe", "All certificates", "", deadline.Token)
                    .Rows.Count == 2 && CertificateInventory.Read(target, "127.0.0.1", "All certificates", "",
                    deadline.Token).Rows.Count == 2, "Certificate search omitted endpoint process or peer evidence.");
                var uses = CertificateInventory.ReadUses(target, inventory.Rows[0].Sha256, deadline.Token);
                Check(uses.Any(use => use.EndpointApplication == @"C:\Java\java.exe" &&
                    use.ClientApplication.Length == 0 && use.ServerApplication.Length == 0) &&
                    uses.All(use => use.Evidence == "Endpoint" && use.ChainIndex == -1),
                    "Application-scoped certificate evidence invented a socket role or chain position.");
                results.Add(new
                {
                    provider = target.Provider.ToString(),
                    observations = snapshot.Total,
                    completed = snapshot.Rows.Sum(row => row.Complete),
                    endpoint_only = 9
                });
            }
        }
        finally
        {
            foreach (var target in targets.Skip(1))
                LabDatabase.DropServerDatabase(target);
        }
        // Packet and endpoint links for the same certificate still describe one negotiation.
        var mixedPath = Path.Combine(directory, "mixed-certificates.db");
        using (var input = (SqliteConnection)local.CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={mixedPath}"))
        {
            input.Open();
            copy.Open();
            input.BackupDatabase(copy);
            using var insert = copy.CreateCommand();
            insert.CommandText = """
                BEGIN IMMEDIATE;
                UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
                INSERT INTO connection_certificates(run_id,flow_id,role,chain_index,sha256,change_revision)
                SELECT run_id,flow_id,'server',0,(SELECT MIN(sha256) FROM certificates),
                    (SELECT revision FROM metadata) FROM connections WHERE flow_id=3;
                COMMIT;
                """;
            insert.ExecuteNonQuery();
        }
        var mixedSource = DatabaseSource.Sqlite(mixedPath);
        var mixed = CertificateInventory.Read(mixedSource, "", "All certificates", "", deadline.Token);
        Check(mixed.Rows.All(row => row.Observations == 7),
            "Packet and endpoint links counted the same certificate negotiation twice.");
        Check(CertificateInventory.ReadUses(mixedSource, mixed.Rows[0].Sha256, deadline.Token)
            .Any(use => use.Evidence == "Packet" && use.Role == "server" && use.ChainIndex == 0),
            "Packet certificate roles were lost while adding endpoint evidence.");
        File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(results,
            new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(JsonSerializer.Serialize(results));
    }

    private static void Check(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
