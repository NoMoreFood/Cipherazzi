using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class AdversarialData
{
    public static async Task RunAsync(string[] args)
    {
        var directory = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "timestamps.db");
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
            using var command = copy.CreateCommand();
            command.CommandText = """
                DELETE FROM connection_certificates;
                DELETE FROM connections WHERE id NOT IN (SELECT id FROM connections ORDER BY id LIMIT 2);
                """;
            command.ExecuteNonQuery();
        }
        var results = new List<object>();
        var source = DatabaseSource.Sqlite(path);
        foreach (var (first, last) in new[] { (long.MinValue, long.MaxValue),
            (long.MinValue, long.MinValue + 1000000), (long.MaxValue - 1000000, long.MaxValue),
            (0L, 600000000L) })
        {
            using (var writer = new SqliteConnection($"Data Source={path};Pooling=False"))
            {
                writer.Open();
                using var command = writer.CreateCommand();
                command.CommandText = "UPDATE connections SET first_us=" +
                    "CASE WHEN id=(SELECT MIN(id) FROM connections) " +
                    "THEN @first ELSE @last END";
                command.Parameters.AddWithValue("@first", first);
                command.Parameters.AddWithValue("@last", last);
                command.ExecuteNonQuery();
            }
            var watch = Stopwatch.StartNew();
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            var rejected = false;
            string? failure = null;
            try
            {
                // Corrupted timestamp ranges must not expand into an unbounded in-memory timeline.
                var snapshot = await Task.Run(() => Insights.ReadAnalytics(source,
                    new Query("", "", false, PageCursor.Newest), 0, "Protocol", 20, cancellation.Token))
                    .WaitAsync(TimeSpan.FromMilliseconds(750));
                if (first != 0 || snapshot.Total != 2 || snapshot.Timeline.Count > 62 ||
                    snapshot.Timeline.Sum(point => point.Count) != 2)
                    throw new InvalidOperationException(
                        "Invalid timestamps were accepted or a valid timeline lost observations.");
            }
            catch (Exception error) when (error is ArgumentOutOfRangeException or InvalidDataException)
            { rejected = true; }
            catch (Exception error) { failure = error.ToString(); }
            var passed = failure is null && (first == 0 ? !rejected : rejected);
            results.Add(new
            {
                first,
                last,
                result = passed ? "passed" : "failed",
                rejected,
                elapsed_ms = watch.Elapsed.TotalMilliseconds,
                failure
            });
            File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
            {
                result = passed ? "passed" : "failed",
                scenarios = results
            }, new JsonSerializerOptions { WriteIndented = true }));
            if (!passed)
                throw new InvalidOperationException("Analytics failed its corrupt-timestamp deadline. " + failure);
        }
        // Damaged metadata retains its observation count without supplying inferred cryptographic evidence.
        using (var writer = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            writer.Open();
            using var command = writer.CreateCommand();
            command.CommandText = """
                UPDATE connections SET sni='',crypto_json=CASE WHEN id=(SELECT min(id) FROM connections)
                    THEN '{broken' ELSE '{"group_class":"Classical","transport":"UDP",
                        "handshake_confirmation":"Not confirmed by endpoint","http_host":"valid.test"}' END
                """;
            command.ExecuteNonQuery();
        }
        foreach (var (dimension, observed) in new[] { ("Group classification", "Classical"),
            ("Transport", "UDP"), ("Endpoint confirmation", "Not confirmed by endpoint"),
            ("Server name", "valid.test") })
        {
            var snapshot = Insights.ReadAnalytics(source, new Query("", "", false, PageCursor.Newest),
                0, dimension, 20, CancellationToken.None);
            if (snapshot.Total != 2 || snapshot.Breakdown.Count != 2 ||
                !snapshot.Breakdown.Any(row => row.Name == observed && row.Count == 1) ||
                !snapshot.Breakdown.Any(row => row.Name == "Not observed" && row.Count == 1))
                throw new InvalidOperationException("Damaged metadata changed the analytics denominator or evidence.");
        }
        results.Add(new { damaged_metadata = "passed", observations = 2, dimensions = 4 });
        File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
        { result = "passed", scenarios = results }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Corrupt timestamps, bounded timelines, and damaged metadata recovery passed.");
    }
}
