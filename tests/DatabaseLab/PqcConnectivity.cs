using System.Data.Common;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class PqcConnectivity
{
    public static async Task RunAsync(string[] args)
    {
        var directory = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "pqc.db");
        using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path}"))
        {
            source.Open();
            copy.Open();
            source.BackupDatabase(copy);
        }
        var local = DatabaseSource.Sqlite(path);
        var complete = ReadEvidence(local);
        var retry = complete.First(pair =>
            JsonNode.Parse(pair.Value)!["negotiation_stages"]!.AsArray().Count == 4);
        var partial = JsonNode.Parse(retry.Value)!;
        var stages = partial["negotiation_stages"]!.AsArray();
        while (stages.Count > 2)
            stages.RemoveAt(stages.Count - 1);
        WriteEvidence(path, retry.Key, partial.ToJsonString());

        // Replicate an in-progress retry, then publish the remaining negotiation stages as a late update.
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var targets = new[]
        {
            DatabaseSource.FromEnvironment("sqlserver", "CIPHERAZZI_SQLSERVER"),
            DatabaseSource.FromEnvironment("postgresql", "CIPHERAZZI_POSTGRESQL")
        };
        for (var index = 0; index < targets.Length; ++index)
        {
            targets[index] = FreshTarget(targets[index]);
            ConnectionCredentials.Save(Path.Combine(directory, targets[index].Provider + ".credential"), targets[index]);
            await Replication.InitializeAsync(targets[index], deadline.Token);
            while ((await Replication.SyncAsync(path, targets[index], deadline.Token)).More) {}
            Assert(ReadEvidence(targets[index])[retry.Key] == partial.ToJsonString(),
                "The in-progress retry history did not replicate.");
        }
        WriteEvidence(path, retry.Key, retry.Value);
        var results = new List<object>();
        foreach (var target in targets.Prepend(local))
        {
            var watch = Stopwatch.StartNew();
            if (target.Provider != DatabaseProvider.Sqlite)
                while ((await Replication.SyncAsync(path, target, deadline.Token)).More) {}
            var actual = ReadEvidence(target);
            Assert(actual.Count == complete.Count && complete.All(pair =>
                actual.TryGetValue(pair.Key, out var value) && value == pair.Value),
                "PQC evidence changed during replication.");
            var expectedRows = Database.Read(local, new Query("", "", false, PageCursor.Newest), deadline.Token);
            var rows = Database.Read(target, new Query("", "", false, PageCursor.Newest), deadline.Token);
            Assert(!rows.HasMore && rows.Rows.Count == complete.Count, "The PQC fixture is not fully visible.");
            var expected = expectedRows.Rows.ToDictionary(row => row.Value("Run") + ":" + row.Value("Flow"));
            foreach (var row in rows.Rows)
            {
                var original = expected[row.Value("Run") + ":" + row.Value("Flow")];
                Assert(row.Values.Count == original.Values.Count && original.Values.All(pair =>
                    row.Value(pair.Key) == pair.Value), "Viewer PQC columns differ between providers.");
                Assert(JsonSerializer.Serialize(row.Properties) == JsonSerializer.Serialize(original.Properties),
                    "Viewer negotiation properties differ between providers.");
            }
            Assert(rows.Rows.Any(row => row.Value("GroupClass") == "Hybrid post-quantum"),
                "The viewer has no hybrid PQC negotiation.");
            if (target.Provider != DatabaseProvider.Sqlite)
            {
                var idle = await Replication.SyncAsync(path, target, deadline.Token);
                Assert(idle.Connections == 0 && !idle.More, "PQC reconnect duplicated an observation.");
            }
            results.Add(new { provider = target.Provider.ToString(), rows = rows.Rows.Count,
                update_and_read_ms = watch.Elapsed.TotalMilliseconds });
        }
        File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
        {
            providers = results, exact_crypto_json = true, late_retry_history = true,
            viewer_columns_and_properties = true, reconnect_idempotent = true, source = path
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"PQC evidence and late negotiation updates verified across {results.Count} providers.");
    }

    private static Dictionary<string, string> ReadEvidence(DatabaseSource source)
    {
        using var connection = source.CreateConnection();
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT run_id,flow_id,crypto_json FROM {source.Prefix}connections";
        using var reader = command.ExecuteReader();
        var result = new Dictionary<string, string>();
        while (reader.Read())
            result.Add(reader.GetString(0) + ":" + reader.GetInt64(1), reader.GetString(2));
        return result;
    }

    private static void WriteEvidence(string path, string key, string evidence)
    {
        using var connection = new SqliteConnection($"Data Source={path}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            BEGIN IMMEDIATE;
            UPDATE metadata SET revision=revision+1;
            UPDATE connections SET crypto_json=@evidence,change_revision=(SELECT revision FROM metadata)
                WHERE run_id=@run AND flow_id=@flow;
            COMMIT;
            """;
        var split = key.LastIndexOf(':');
        command.Parameters.AddWithValue("@run", key[..split]);
        command.Parameters.AddWithValue("@flow", long.Parse(key[(split + 1)..]));
        command.Parameters.AddWithValue("@evidence", evidence);
        command.ExecuteNonQuery();
    }

    internal static DatabaseSource FreshTarget(DatabaseSource target)
    {
        // Each run gets an isolated database without changing any existing lab inventory.
        var name = "CipherazziPqc_" + Guid.NewGuid().ToString("N")[..10];
        var builder = target.Provider == DatabaseProvider.SqlServer ?
            (DbConnectionStringBuilder)new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(target.ConnectionString) :
            new Npgsql.NpgsqlConnectionStringBuilder(target.ConnectionString);
        var databaseKey = target.Provider == DatabaseProvider.SqlServer ? "Initial Catalog" : "Database";
        builder[databaseKey] = target.Provider == DatabaseProvider.SqlServer ? "master" : "postgres";
        using var connection = new DatabaseSource(target.Provider, builder.ConnectionString).CreateConnection();
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = target.Provider == DatabaseProvider.SqlServer ?
            $"CREATE DATABASE [{name}]" : $"CREATE DATABASE \"{name}\"";
        command.ExecuteNonQuery();
        builder[databaseKey] = name;
        return new(target.Provider, builder.ConnectionString);
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
