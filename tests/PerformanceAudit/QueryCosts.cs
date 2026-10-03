using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Cipherazzi.Data;

internal static class QueryCosts
{
    public static void Run(string path, string output)
    {
        var source = DatabaseSource.Sqlite(path);
        string Sql(string name) => (string)typeof(PqcInsights).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [source])!;
        var profile = Sql("CryptoProfile");
        var certificate = Sql("CertificateFacts");
        using var connection = source.CreateConnection();
        connection.Open();
        var results = new List<object>();
        foreach (var (name, expression) in new[]
        {
            ("plain_scan", "c.sni"), ("single_json_field", "json_extract(c.crypto_json,'$.group_class')"),
            ("certificate_facts", certificate), ("normalized_profile", profile),
            ("binary_profile", profile.Replace("JSON_OBJECT", "JSONB_OBJECT").Replace("JSON_GROUP_ARRAY", "JSONB_GROUP_ARRAY"))
        })
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT {expression} FROM connections c";
            var watch = Stopwatch.StartNew();
            var count = 0;
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                _ = reader.GetValue(0);
                ++count;
            }
            results.Add(new { name, rows = count, elapsed_ms = watch.Elapsed.TotalMilliseconds });
            Console.WriteLine($"{name}: {watch.Elapsed.TotalMilliseconds:N2} ms");
        }
        File.WriteAllText(output, JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
    }
}
