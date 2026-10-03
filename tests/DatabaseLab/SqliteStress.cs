using System.Data.Common;
using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class SqliteStress
{
    public static async Task RunAsync(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "slow.db");
        using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            source.Open();
            copy.Open();
            source.BackupDatabase(copy);
            using var command = copy.CreateCommand();
            command.CommandText = """
                ALTER TABLE connections RENAME TO stored_connections;
                CREATE VIEW connections AS
                    WITH RECURSIVE copies(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM copies WHERE n<10000)
                    SELECT c.* FROM stored_connections c CROSS JOIN copies;
                """;
            command.ExecuteNonQuery();
        }
        var watch = Stopwatch.StartNew();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var canceled = false;
        string? failure = null;
        try
        {
            // A large aggregate stays inside SQLite without returning rows to managed cancellation checks.
            await Task.Run(() => Insights.ReadAnalytics(DatabaseSource.Sqlite(path),
                new Query("", "", false, PageCursor.Newest), 0, "Protocol", 20, cancellation.Token))
                .WaitAsync(TimeSpan.FromSeconds(3));
        }
        catch (OperationCanceledException) { canceled = true; }
        catch (DbException) when (cancellation.IsCancellationRequested) { canceled = true; }
        catch (Exception error) { failure = error.ToString(); }
        var cancellationMilliseconds = watch.Elapsed.TotalMilliseconds;
        var measurements = new Dictionary<string, double>();
        if (canceled)
        {
            var normal = DatabaseSource.Sqlite(args[0]);
            using var active = new CancellationTokenSource();
            foreach (var (name, token) in new[] { ("without_cancellation", CancellationToken.None),
                ("with_cancellation", active.Token) })
            {
                var query = new Query("", "", false, PageCursor.Newest);
                Database.Read(normal, query, token);
                Insights.ReadAnalytics(normal, query, 0, "Protocol", 20, token);
                var performance = Stopwatch.StartNew();
                for (var index = 0; index < 12; ++index)
                {
                    Database.Read(normal, query, token);
                    Insights.ReadAnalytics(normal, query, 0, "Protocol", 20, token);
                }
                measurements[name + "_read_and_analytics_ms"] = performance.Elapsed.TotalMilliseconds / 12;
            }
        }
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        {
            result = canceled ? "passed" : "failed", scenario = "cancel_native_sqlite_aggregate",
            elapsed_ms = cancellationMilliseconds, failure, measurements
        }, new JsonSerializerOptions { WriteIndented = true }));
        if (!canceled)
            throw new InvalidOperationException("SQLite continued its aggregate after cancellation.");
        Console.WriteLine($"SQLite aggregate canceled in {cancellationMilliseconds:F0} ms.");
    }
}
