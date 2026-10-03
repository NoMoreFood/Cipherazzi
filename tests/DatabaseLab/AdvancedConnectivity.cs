using System.Data.Common;
using System.Text.Json;
using Cipherazzi.Data;

internal static class AdvancedConnectivity
{
    public static async Task RunAsync(string[] args)
    {
        var directory = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(directory);
        var source = DatabaseSource.Sqlite(Path.GetFullPath(args[0]));
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var targets = new[]
        {
            DatabaseSource.FromEnvironment("sqlserver", "CIPHERAZZI_SQLSERVER"),
            DatabaseSource.FromEnvironment("postgresql", "CIPHERAZZI_POSTGRESQL")
        };
        var expected = Evidence(source);
        var results = new List<object>();
        foreach (var original in targets)
        {
            var target = PqcConnectivity.FreshTarget(original);
            ConnectionCredentials.Save(Path.Combine(directory, target.Provider + ".credential"), target);
            await Replication.InitializeAsync(target, deadline.Token);
            while ((await Replication.SyncAsync(args[0], target, deadline.Token)).More) {}
            Assert(expected.SequenceEqual(Evidence(target)), "Public endpoint evidence or certificate DER changed in replication.");
            var query = new Query("Endpoint confirmed", "", false, PageCursor.Newest);
            var rows = Database.Read(target, query, deadline.Token).Rows;
            Assert(rows.Count == 10 && rows.Count(row => row.Value("Transport") == "QUIC") == 2,
                "Transport data did not reach the viewer.");
            Assert(rows.Count(row => row.Value("Confirmation") == "Endpoint confirmed completion") == 8 &&
                rows.Count(row => row.Value("Confirmation") == "Endpoint confirmed failure") == 2,
                "Endpoint outcomes did not reach the viewer.");
            Assert(rows.Count(row => row.Value("EndpointAuthClass") == "Post-quantum") == 6,
                "Endpoint signature classification did not reach the viewer.");
            Assert(rows.Where(row => row.Value("Confirmation") == "Endpoint confirmed completion")
                .All(row => row.Certificates.Length > 0), "Endpoint certificate references were lost.");
            Assert(rows.Count(row => row.Value("EndpointLocalSignature") == "mldsa65" &&
                row.Value("EndpointLocalAuthClass") == "Post-quantum") == 1,
                "Mutual PQ authentication signatures were lost.");
            Assert(Database.Read(target, new Query("QUIC", "", false, PageCursor.Newest), deadline.Token).Rows.Count == 2,
                "QUIC search did not match the transport analytics filter.");
            Assert(Database.Read(target, new Query("Endpoint confirmed failure", "", false, PageCursor.Newest),
                deadline.Token).Rows.Count == 2, "Endpoint outcome search lost a failure.");
            var transport = Insights.ReadAnalytics(target, query,
                0, "Transport", 20, deadline.Token);
            Assert(transport.Breakdown.Count == 2 && transport.Breakdown.Sum(row => row.Count) == 10,
                "Transport analytics did not match the captured inventory.");
            var outcomes = Insights.ReadAnalytics(target, query,
                0, "Endpoint confirmation", 20, deadline.Token);
            Assert(outcomes.Breakdown.Count == 2, "Endpoint analytics lost an outcome.");
            results.Add(new { provider = target.Provider.ToString(), rows = rows.Count,
                exact_json_and_der = true, endpoint_certificates = true, transport_and_confirmation_analytics = true });
        }
        File.WriteAllText(Path.Combine(directory, "results.json"),
            JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("SQL Server and PostgreSQL: QUIC, endpoint outcomes, PQ authentication, and certificate DER passed.");
    }

    private static string[] Evidence(DatabaseSource source)
    {
        using var connection = source.CreateConnection();
        connection.Open();
        var result = new List<string>();
        foreach (var (table, key, fields) in new[]
        {
            ("connections", "run_id,flow_id", "run_id,flow_id,crypto_json"),
            ("endpoint_events", "id", "id,detail_json"),
            ("certificates", "sha256", "sha256,metadata_json,der")
        })
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT {fields} FROM {source.Prefix}{table} ORDER BY {key}";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var values = new object[reader.FieldCount];
                reader.GetValues(values);
                result.Add(table + ":" + string.Join('|', values.Select(value => value is byte[] bytes ?
                    Convert.ToBase64String(bytes) : value.ToString())));
            }
        }
        return result.ToArray();
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
