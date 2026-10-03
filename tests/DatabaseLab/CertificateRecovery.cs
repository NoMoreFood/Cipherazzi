using System.Diagnostics;
using System.Text.Json;
using System.Text;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

internal static class CertificateRecovery
{
    public static async Task RunAsync(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "certificate-metadata.db");

        // Vary catalog metadata while retaining real certificate bytes and observation usage.
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        {
            original.Open();
            connection.Open();
            original.BackupDatabase(connection);
        }
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT sha256,metadata_json FROM certificates ORDER BY sha256 LIMIT 1";
        string hash, metadata;
        using (var reader = command.ExecuteReader())
        {
            reader.Read();
            hash = reader.GetString(0);
            metadata = reader.GetString(1);
        }
        using var document = JsonDocument.Parse(metadata);
        var subject = document.RootElement.GetProperty("subject").GetString();
        var issuer = document.RootElement.GetProperty("issuer").GetString();
        var notBefore = document.RootElement.GetProperty("not_before_us").GetInt64();
        var notAfter = document.RootElement.GetProperty("not_after_us").GetInt64();
        var providerOption = Array.IndexOf(args, "--provider");
        var source = providerOption < 0 ? DatabaseSource.Sqlite(path) :
            DatabaseSource.FromEnvironment(args[providerOption + 1], "CIPHERAZZI_CONNECTION");
        if (source.Provider != DatabaseProvider.Sqlite)
        {
            var database = source.Provider == DatabaseProvider.SqlServer ?
                new SqlConnectionStringBuilder(source.ConnectionString).InitialCatalog :
                new NpgsqlConnectionStringBuilder(source.ConnectionString).Database;
            if (database?.StartsWith("CipherazziMetadata_", StringComparison.Ordinal) != true)
                throw new InvalidOperationException("Use an isolated CipherazziMetadata_ database.");
            await Replication.InitializeAsync(source, CancellationToken.None);
            while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
        }
        var der = CertificateInventory.ReadDer(source, hash, CancellationToken.None);
        var baseline = args.Contains("--baseline");
        var results = new List<object>();
        var failures = 0;
        string Wide(int count, bool duplicate = false) => "{" + string.Join(',', Enumerable.Range(0, count)
            .Select(index => "\"" + (duplicate ? "duplicate" : "extra_" + index) + "_us\":0")) +
            "," + metadata.TrimStart()[1..];
        foreach (var (name, json, limited) in new[]
        {
            ("healthy", metadata, false),
            ("wide-2000", Wide(2000), true),
            ("wide-8000", Wide(8000), true),
            ("wide-16000", Wide(16000), true),
            ("duplicate-16000", Wide(16000, true), true),
            ("array-200000", "{\"extra_array\":" + JsonSerializer.Serialize(Enumerable.Repeat("x", 200000)) +
                "," + metadata.TrimStart()[1..], true),
            ("string-1000000", "{\"extra_text\":" + JsonSerializer.Serialize(new string('x', 1000000)) +
                "," + metadata.TrimStart()[1..], true),
            ("aggregate-values", "{" + string.Join(',', Enumerable.Range(0, 64).Select(index =>
                "\"extra_" + index + "\":" + JsonSerializer.Serialize(new string('x', 8192)))) +
                "," + metadata.TrimStart()[1..], true),
            ("long-name", "{" + JsonSerializer.Serialize(new string('n', 128000)) + ":0," +
                metadata.TrimStart()[1..], true),
            ("unicode-boundary", "{\"extra_text\":" +
                JsonSerializer.Serialize(new string('x', 16382) + "😀 text beyond the boundary") + "," +
                metadata.TrimStart()[1..], true),
            ("unicode-subject", metadata.Replace("\"subject\":" +
                document.RootElement.GetProperty("subject").GetRawText(), "\"subject\":\"\\ud800\""), true),
            ("unicode-name", "{\"\\ud800\":0," + metadata.TrimStart()[1..], true),
            ("unicode-array", "{\"extra_array\":[\"\\udc00\"]," + metadata.TrimStart()[1..], true)
        })
        {
            var caseOption = Array.IndexOf(args, "--case");
            if (caseOption >= 0 && !name.StartsWith(args[caseOption + 1], StringComparison.Ordinal))
                continue;
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

            // Exercise both production readers and keep display limits separate from preserved evidence.
            var checks = new List<object>();
            foreach (var operation in new[] { "inventory", "connection-details" })
            {
                var watch = Stopwatch.StartNew();
                var passed = false;
                string? error = null;
                var count = 0;
                var longest = 0;
                var characters = 0;
                try
                {
                    var inventory = operation == "inventory" ? CertificateInventory.Read(source, "",
                        "All certificates", "", CancellationToken.None).Rows.Single(row => row.Sha256 == hash) : null;
                    var properties = inventory?.Properties ??
                        Insights.ReadCertificates(source, ["Server 1|" + hash], CancellationToken.None);
                    count = properties.Count;
                    longest = properties.Select(property => property.Value.Length).DefaultIfEmpty().Max();
                    characters = properties.Sum(property => property.Value.Length);
                    var subjectMatches = name == "unicode-subject" ?
                        properties.All(property => property.Name != "Subject") &&
                            (inventory is null || inventory.Subject.Length == 0) :
                        properties.Any(property => property.Name == "Subject" && property.Value == subject);
                    passed = subjectMatches &&
                        properties.Any(property => property.Name == "Issuer" && property.Value == issuer) &&
                        properties.Any(property => property.Name == "SHA-256" && property.Value == hash) &&
                        (inventory is null || inventory.NotBeforeUs == notBefore && inventory.NotAfterUs == notAfter) &&
                        CertificateInventory.ReadDer(source, hash, CancellationToken.None).SequenceEqual(der);
                    if (!baseline)
                        passed &= count <= 512 && longest <= 65536 && characters <= 100000 &&
                            properties.All(property => property.Name.Length <= 1024) &&
                            (!limited || properties.Any(property => property.Name == "Metadata"));
                    var utf8 = new UTF8Encoding(false, true);
                    foreach (var property in properties)
                        utf8.GetByteCount(property.Value);
                }
                catch (Exception failure) { error = failure.ToString(); }
                var elapsed = watch.Elapsed.TotalMilliseconds;
                checks.Add(new { operation, passed, elapsed_ms = elapsed, properties = count,
                    longest_value = longest, characters, error });
                if (!passed)
                    ++failures;
                Console.WriteLine($"{name} {operation}: {elapsed:F1} ms; {count} properties; longest={longest}");
            }
            results.Add(new { name, metadata_characters = json.Length, checks });
        }
        // Leave the isolated journal and replica ready for subsequent checks against the same public fixture.
        command.Parameters.Clear();
        command.CommandText = """
            UPDATE metadata SET revision=revision+1,observation_revision=revision+1;
            UPDATE certificates SET metadata_json=@json,change_revision=(SELECT revision FROM metadata)
                WHERE sha256=@hash;
            """;
        command.Parameters.AddWithValue("@json", metadata);
        command.Parameters.AddWithValue("@hash", hash);
        command.ExecuteNonQuery();
        if (source.Provider != DatabaseProvider.Sqlite)
            while ((await Replication.SyncAsync(path, source, CancellationToken.None)).More) { }
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        { passed = failures == 0, baseline, provider = source.Provider.ToString(), cases = results },
            new JsonSerializerOptions { WriteIndented = true }));
        if (failures != 0)
            throw new InvalidOperationException($"{failures} certificate metadata checks failed.");
    }
}
