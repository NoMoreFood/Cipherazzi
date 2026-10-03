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
        var canceled = true;
        string? failure = null;
        var cancellations = new Dictionary<string, double>();
        var scenarios = new List<object>();
        var slow = DatabaseSource.Sqlite(path);
        var query = new Query("", "", false, PageCursor.Newest);
        foreach (var (name, read) in new (string, Func<CancellationToken, object>)[]
        {
            ("analytics", token => Insights.ReadAnalytics(slow, query, 0, "Protocol", 20, token)),
            ("readiness", token => PqcInsights.Read(slow, query, 0, long.MaxValue,
                "Client application", [new CryptoPolicy()], token))
        })
        {
            var watch = Stopwatch.StartNew();
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            var stopped = false;
            int? sqliteError = null;
            string? errorText = null;
            try
            {
                // Aggregates must stop inside SQLite, before a first result reaches managed cancellation checks.
                await Task.Run(() => read(cancellation.Token)).WaitAsync(TimeSpan.FromSeconds(3));
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { stopped = true; }
            catch (SqliteException error) when (cancellation.IsCancellationRequested &&
                error.SqliteErrorCode == SQLitePCL.raw.SQLITE_INTERRUPT)
            { stopped = true; sqliteError = error.SqliteErrorCode; }
            catch (Exception error) { errorText = error.ToString(); }
            cancellations[name] = watch.Elapsed.TotalMilliseconds;
            scenarios.Add(new { name, canceled = stopped, elapsed_ms = cancellations[name],
                sqlite_error_code = sqliteError, failure = errorText });
            canceled &= stopped;
            failure ??= errorText;
        }
        var measurements = new Dictionary<string, double>();
        if (canceled)
        {
            var normal = DatabaseSource.Sqlite(args[0]);
            using var active = new CancellationTokenSource();
            foreach (var (name, token) in new[] { ("without_cancellation", CancellationToken.None),
                ("with_cancellation", active.Token) })
            {
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
            result = canceled ? "passed" : "failed",
            scenario = "cancel_native_sqlite_aggregate",
            elapsed_ms = cancellations["analytics"],
            failure,
            scenarios,
            measurements
        }, new JsonSerializerOptions { WriteIndented = true }));
        if (!canceled)
            throw new InvalidOperationException("SQLite aggregate cancellation checks failed. " + failure);
        Console.WriteLine("SQLite aggregates canceled: " + string.Join(", ",
            cancellations.Select(item => $"{item.Key} {item.Value:F0} ms")) + ".");
    }
}
