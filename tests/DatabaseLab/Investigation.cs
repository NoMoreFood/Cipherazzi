using System.Text;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.VisualBasic.FileIO;
using Npgsql;

internal static class Investigation
{
    private static readonly string searchPath = "C:/" +
        string.Join('/', Enumerable.Repeat(new string('K', 62), 4)) + ".x";
    private static readonly string searchHost =
        string.Join('.', Enumerable.Repeat(new string('K', 63), 3)) + "." + new string('K', 61) + ":80";

    private sealed class ProgressCallback(Action<long> action) : IProgress<long>
    {
        public void Report(long value) => action(value);
    }

    public static void Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "investigation.db");
        using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            source.Open();
            copy.Open();
            source.BackupDatabase(copy);
            using var command = copy.CreateCommand();
            command.CommandText = "SELECT min(first_us),max(first_us),count(*) FROM connections";
            long first, last, total;
            using (var reader = command.ExecuteReader())
            {
                reader.Read();
                first = reader.GetInt64(0);
                last = reader.GetInt64(1);
                total = reader.GetInt64(2);
            }
            if (total < 1000)
                throw new ArgumentException("Use the ten-scenario migration fixture with at least 1000 observations.");
            command.CommandText = "DELETE FROM endpoint_events; SELECT run_id,flow_id FROM connections LIMIT 1";
            string run;
            long flow;
            using (var reader = command.ExecuteReader())
            {
                reader.Read();
                run = reader.GetString(0);
                flow = reader.GetInt64(1);
            }

            // Include matched, server-side, and role-unknown endpoint evidence across more than one displayed page.
            using var transaction = copy.BeginTransaction();
            command.Transaction = transaction;
            for (var index = 0; index < 600; index++)
            {
                var server = index % 3 == 1;
                var unknown = index % 3 == 2;
                var detail = new Dictionary<string, object>
                {
                    ["role"] = unknown ? "unknown" : server ? "server" : "client",
                    ["transport"] = "TCP",
                    ["local"] = new { address = server ? "192.0.2.2" : "192.0.2.1", port = server ? 443 : 45000 },
                    ["remote"] = new { address = server ? "192.0.2.1" : "192.0.2.2", port = server ? 45000 : 443 },
                    ["assessment"] = new
                    {
                        first_us = first + index,
                        last_us = first + index + 500,
                        tls_version = 772,
                        local_role = unknown ? "Unknown" : server ? "Server" : "Client",
                        process = "endpoint-Δ.exe",
                        path = "C:/Lab/endpoint-Δ.exe",
                        server_name = "endpoint.test",
                        server_port = 443,
                        group_name = "X25519",
                        key_exchange = "ECDHE",
                        authentication = "",
                        certificate_facts = "",
                        crypto = new
                        {
                            protocol = "TLS",
                            transport = "TCP",
                            evidence_source = "Endpoint",
                            group_class = "Classical",
                            endpoint_confirmations = new[] { new { success = true,
                                local_role = server ? "Server" : "Client", peer_verified = 1 } }
                        }
                    }
                };
                if (index % 3 == 0)
                {
                    detail["matched_run_id"] = run;
                    detail["matched_flow_id"] = flow;
                }
                command.Parameters.Clear();
                command.CommandText = """
                    INSERT INTO endpoint_events(id,run_id,timestamp_us,provider,kind,result,
                        pid,peer,port,protocol,cipher,
                        certificate_id,detail_json,change_revision)
                    VALUES(@id,@run,@time,'Investigation adapter','TLS','Reported completion',1234,'endpoint.test',443,
                        'TLS 1.3','TLS_AES_128_GCM_SHA256','',@detail,1)
                    """;
                command.Parameters.AddWithValue("@id", "investigation-" + index.ToString("D4"));
                command.Parameters.AddWithValue("@run", run);
                command.Parameters.AddWithValue("@time", first + index + 500);
                command.Parameters.AddWithValue("@detail", JsonSerializer.Serialize(detail));
                command.ExecuteNonQuery();
            }
            transaction.Commit();
            command.Transaction = null;
            command.Parameters.Clear();
            command.CommandText = "UPDATE connections SET sni=@text WHERE id=(SELECT min(id) FROM connections)";
            command.Parameters.AddWithValue("@text", "=literal_%[x]'Δ\r\nsecond line");
            command.ExecuteNonQuery();

            // Exercise ASCII and Unicode folding in both broad searches and literal field filters.
            foreach (var text in new[] { "SEARCHCHECK-ascii_%[y]'\\-aAaAaB", "SEARCHCHECK-Kelvin-Δ-𐐀",
                "SEARCHCHECK-accent-É", "SEARCHCHECK-width-Ａ", "SEARCHCHECK-tail ", "SEARCHCHECK-sigma-Σ",
                "SEARCHCHECK-hungarian-\U00010CB0", "SEARCHCHECK-dotted-İ", "SEARCHCHECK-ligature-Ĳ" })
            {
                command.Parameters.Clear();
                command.CommandText = "UPDATE connections SET sni=@text WHERE id=(SELECT min(id) FROM connections " +
                    "WHERE sni='case-0.migration.test')";
                command.Parameters.AddWithValue("@text", text);
                command.ExecuteNonQuery();
            }
            command.Parameters.Clear();
            command.CommandText = "UPDATE connections SET sni='SEARCHCHECK-long-fields',source_path=@text," +
                "crypto_json=json_set(crypto_json,'$.http_host',@host) WHERE id=(SELECT min(id) " +
                "FROM connections WHERE sni='case-0.migration.test')";
            command.Parameters.AddWithValue("@text", searchPath);
            command.Parameters.AddWithValue("@host", searchHost);
            command.ExecuteNonQuery();

            // Preserve default transport and escaped JSON keys and values when searching metadata.
            command.Parameters.Clear();
            command.CommandText = "UPDATE connections SET sni='SEARCHCHECK-default-transport',crypto_json='{}' " +
                "WHERE id=(SELECT min(id) FROM connections WHERE sni='case-0.migration.test')";
            command.ExecuteNonQuery();
            command.CommandText = """
                UPDATE connections SET sni='SEARCHCHECK-escaped-json',
                    crypto_json=replace(json_set(crypto_json,'$.http_hosts',json(@hosts)),
                        '"http_hosts"','"\u0068ttp_hosts"')
                WHERE id=(SELECT min(id) FROM connections WHERE sni='case-0.migration.test')
                """;
            command.Parameters.AddWithValue("@hosts", "[\"\\u0065scaped-alias.test\"]");
            command.ExecuteNonQuery();
            command.Parameters.Clear();
            command.CommandText = """
                UPDATE connections SET sni='SEARCHCHECK-padded-host-key',
                    crypto_json=json_set(crypto_json,'$.http_hosts ',json('["padded-alias.test"]'))
                WHERE id=(SELECT min(id) FROM connections WHERE sni='case-0.migration.test');
                UPDATE connections SET sni='SEARCHCHECK-neighbor-host-key',
                    crypto_json=json_set(crypto_json,'$.http_hosts',json('["valid-neighbor.test"]'),
                        '$.http_hosts ',json('["padded-neighbor.test"]'))
                WHERE id=(SELECT min(id) FROM connections WHERE sni='case-0.migration.test');
                """;
            command.ExecuteNonQuery();
            File.WriteAllText(Path.Combine(output, "bounds.json"),
                JsonSerializer.Serialize(new { first, last, total }));
        }
        var database = DatabaseSource.Sqlite(path);
        Verify(database, output);
    }

    public static async Task RunRemoteAsync(string[] args)
    {
        var source = DatabaseSource.FromEnvironment(args[2], "CIPHERAZZI_CONNECTION");
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var name = "CipherazziInvestigation_" + Guid.NewGuid().ToString("N")[..12];
        DatabaseSource admin, target;
        if (source.Provider == DatabaseProvider.SqlServer)
        {
            var builder = new SqlConnectionStringBuilder(source.ConnectionString) { InitialCatalog = "master" };
            admin = new(source.Provider, builder.ConnectionString);
            builder.InitialCatalog = name;
            target = new(source.Provider, builder.ConnectionString);
        }
        else
        {
            var builder = new NpgsqlConnectionStringBuilder(source.ConnectionString) { Database = "postgres" };
            admin = new(source.Provider, builder.ConnectionString);
            builder.Database = name;
            target = new(source.Provider, builder.ConnectionString);
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        using var connection = await admin.OpenConnectionAsync(deadline.Token);
        using var command = connection.CreateCommand();
        command.CommandTimeout = 15;
        command.CommandText = source.Provider == DatabaseProvider.SqlServer ?
            $"CREATE DATABASE [{name}]" : $"CREATE DATABASE \"{name}\"";
        await command.ExecuteNonQueryAsync(deadline.Token);
        try
        {
            // Replicate capture evidence into a fresh database and exercise production readers and exports.
            await Replication.InitializeAsync(target, deadline.Token);
            while ((await Replication.SyncAsync(args[0], target, deadline.Token)).More) { }
            Verify(target, output);
            await VerifyConcurrentAnalyticsAsync(target, output, deadline.Token);
            await VerifyConcurrentReadinessAsync(target, output, deadline.Token);
            await VerifyConcurrentExportAsync(target, output);
            if (target.Provider == DatabaseProvider.SqlServer)
                await VerifyFilteredDelayAsync(target, output, deadline.Token);
            File.WriteAllText(Path.Combine(output, "server.json"), JsonSerializer.Serialize(new
            {
                provider = target.Provider.ToString(),
                version = connection.ServerVersion,
                database = name,
                isolated = true
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally
        {
            // Drop only this invocation's generated database and release pooled connections before cleanup.
            if (source.Provider == DatabaseProvider.SqlServer)
                SqlConnection.ClearAllPools();
            else
                NpgsqlConnection.ClearAllPools();
            command.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]" :
                $"DROP DATABASE \"{name}\" WITH (FORCE)";
            await command.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }

    private static async Task VerifyFilteredDelayAsync(DatabaseSource target, string output,
        CancellationToken cancellation)
    {
        // Schema maintenance can block a filtered read longer than a small unfiltered-page timeout.
        using var connection = await target.OpenConnectionAsync(cancellation);
        using var transaction = await connection.BeginTransactionAsync(cancellation);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "ALTER TABLE cipherazzi.connections ADD reader_delay_probe bigint NULL";
        await command.ExecuteNonQueryAsync(cancellation);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var reading = Task.Run(() => Database.Read(target, new Query("", "", false, PageCursor.Newest)
        {
            Conditions = [new(ObservationField.ServerPort, FilterComparison.Equals, "443")]
        }, cancellation), cancellation);
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(6));
        }
        finally
        {
            await transaction.RollbackAsync(CancellationToken.None);
        }
        var snapshot = await reading.WaitAsync(TimeSpan.FromSeconds(15), cancellation);
        if (snapshot.Rows.Count == 0)
            throw new InvalidOperationException("A filtered read lost its scope after schema maintenance.");
        File.WriteAllText(Path.Combine(output, "filtered-delay.json"), JsonSerializer.Serialize(new
        { delay_ms = 6000, elapsed_ms = watch.Elapsed.TotalMilliseconds, rows = snapshot.Rows.Count }));
        Console.WriteLine("Filtered read survived schema maintenance.");
    }

    private static void Verify(DatabaseSource database, string output)
    {
        // Read the authoritative bounds from each provider instead of depending on a local fixture sidecar.
        long firstUs, lastUs, all;
        using (var connection = database.OpenConnectionAsync(CancellationToken.None).GetAwaiter().GetResult())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = $"SELECT min(first_us),max(first_us),count(*) FROM {database.Prefix}connections";
            using var reader = command.ExecuteReader();
            reader.Read();
            firstUs = Convert.ToInt64(reader[0]);
            lastUs = Convert.ToInt64(reader[1]);
            all = Convert.ToInt64(reader[2]);
        }
        var checks = new List<string>();
        void Check(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException(message);
            checks.Add(message);
        }
        var query = new Query("", "", false, PageCursor.Newest);
        var reference = Database.Read(database, query, CancellationToken.None).Rows
            .SelectMany(row => row.Certificates).First();
        var hash = reference.Split('|', 2)[1];
        var single = Insights.ReadCertificates(database, ["server|" + hash], CancellationToken.None);
        var repeated = Insights.ReadCertificates(database,
            ["server|" + hash, "invalid", "client|" + hash, "server|missing"], CancellationToken.None);
        Check(single.Count > 0 && repeated.Count == single.Count * 2 &&
            repeated.Take(single.Count).SequenceEqual(single) &&
            repeated.Skip(single.Count).SequenceEqual(single.Select(property => property with
            { Category = "client certificate" })),
            "Batched certificate details preserve reference order and roles while skipping missing references");
        var scoped = query with
        {
            FromUs = firstUs,
            ToUs = lastUs,
            Conditions =
            [new(ObservationField.ServerName, FilterComparison.Equals, "CASE-1.MIGRATION.TEST"),
             new(ObservationField.ClientProcess, FilterComparison.Contains, "CLIENT"),
             new(ObservationField.ServerPort, FilterComparison.Equals, "443")]
        };

        // Verify the full filtered population through the same bounded cursor pages as the viewer.
        long matched = 0;
        var before = PageCursor.Newest;
        for (;;)
        {
            var page = Database.Read(database, scoped with { Before = before }, CancellationToken.None);
            foreach (var row in page.Rows)
            {
                if (row.Value("Sni") != "case-1.migration.test" || row.FirstUs > before.Time ||
                    (row.FirstUs == before.Time && row.Id >= before.Id))
                    throw new InvalidOperationException("Filtered connection pages lost their scope or cursor order.");
                before = new(row.FirstUs, row.Id);
                ++matched;
            }
            if (!page.HasMore)
                break;
            if (page.Rows.Count == 0)
                throw new InvalidOperationException("A connection page did not advance its cursor.");
        }
        Check(matched == all / 10,
            "Date and typed conditions intersect across the full observation scope");
        var analytics = Insights.ReadAnalytics(database, scoped, lastUs + 1, "Protocol", 20, CancellationToken.None);
        Check(analytics.Total == all / 10, "Explicit dates replace an analytics preset outside the chosen range");
        var readiness = PqcInsights.Read(database, scoped, lastUs + 1, lastUs + 2, "Client application",
            [new CryptoPolicy()], CancellationToken.None);
        Check(readiness.Total == all / 10 && readiness.PolicyObservations == all / 10,
            "Readiness and policy evaluation use the same date and field conditions as connections");
        var mismatch = scoped with
        {
            Conditions = [.. scoped.Conditions,
            new(ObservationField.KeyClass, FilterComparison.Equals, "Classical")]
        };
        Check(Database.Read(database, mismatch, CancellationToken.None).Rows.Count == 0,
            "An additional contradictory field condition cannot widen the scope");
        var literal = query with
        {
            Conditions = [new(ObservationField.ServerName,
            FilterComparison.Contains, "_%[x]'")]
        };
        Check(Database.Read(database, literal, CancellationToken.None).Rows.Count == 1,
            "Filter values containing quotes and SQL wildcard punctuation remain literal");
        Check(Database.Read(database, query with { Search = "_%[x]'δ" }, CancellationToken.None).Rows.Count == 1,
            "Text search applies Unicode case matching while preserving literal wildcard punctuation");
        Check(Database.Read(database, query with
        {
            Conditions =
            [new(ObservationField.ServerName, FilterComparison.StartsWith, "=LITERAL_%[x]'δ\r\n")]
        },
            CancellationToken.None).Rows.Count == 1,
            "Prefix filters preserve Unicode folding, control characters, and literal wildcard punctuation");
        foreach (var text in new[] { "searchcheck-ASCII_%[y]'\\-", "searchcheck-kelvin-δ-𐐨",
            "searchcheck-accent-é", "searchcheck-width-ａ", "searchcheck-hungarian-\U00010CF0",
            "searchcheck-dotted-İ", "searchcheck-ligature-ĳ",
            searchHost.ToLowerInvariant() })
            Check(Database.Read(database, query with { Search = text }, CancellationToken.None).Rows.Count == 1,
                "Broad searches preserve literal punctuation and invariant folding: " + text);
        foreach (var (comparison, text, expected) in new[]
        {
            (FilterComparison.StartsWith, "searchcheck-ASCII_%[y]'\\-", 1),
            (FilterComparison.StartsWith, "SEARCHCHECK-k", 1),
            (FilterComparison.Contains, "aaaab", 1),
            (FilterComparison.Contains, "aaaaac", 0),
            (FilterComparison.Contains, "_%[", 2),
            (FilterComparison.StartsWith, "=", 1),
            (FilterComparison.Contains, "\\", 1),
            (FilterComparison.Equals, "=", 0),
            (FilterComparison.Equals, "searchcheck-kelvin-δ-𐐨", 1),
            (FilterComparison.Equals, "searchcheck-accent-é", 1),
            (FilterComparison.Equals, "searchcheck-width-ａ", 1),
            (FilterComparison.Equals, "searchcheck-hungarian-\U00010CF0", 1),
            (FilterComparison.Equals, "searchcheck-dotted-İ", 1),
            (FilterComparison.Contains, "searchcheck-dotted-i", 0),
            (FilterComparison.Equals, "searchcheck-ligature-ĳ", 1),
            (FilterComparison.Contains, "searchcheck-ligature-ij", 0),
            (FilterComparison.Equals, "searchcheck-tail ", 1),
            (FilterComparison.Equals, "searchcheck-tail", 0),
            (FilterComparison.Contains, "searchcheck-accent-e\u0301", 0),
            (FilterComparison.Equals, "searchcheck-accent-e\u0301", 0),
            (FilterComparison.Contains, "searchcheck-width-a", 0),
            (FilterComparison.Equals, "searchcheck-width-a", 0),
            (FilterComparison.Contains, "searchcheck-sigma-σ", 1),
            (FilterComparison.Contains, "searchcheck-sigma-ς", 0),
            (FilterComparison.Equals, "escaped-alias.test", 1),
            (FilterComparison.Equals, "padded-alias.test", 0),
            (FilterComparison.Equals, "valid-neighbor.test", 1),
            (FilterComparison.Equals, "padded-neighbor.test", 0)
        })
            Check(Database.Read(database, query with
            {
                Conditions = [new(ObservationField.ServerName, comparison, text)]
            }, CancellationToken.None).Rows.Count == expected,
                "Text filters preserve invariant case and literal character boundaries: " + text);
        foreach (var (comparison, text, expected) in new[]
        {
            (FilterComparison.Equals, searchPath.ToLowerInvariant(), 1),
            (FilterComparison.Contains, searchPath.ToLowerInvariant()[..^1] + "y", 0)
        })
            Check(Database.Read(database, query with
            {
                Conditions = [new(ObservationField.ClientProcess, comparison, text)]
            }, CancellationToken.None).Rows.Count == expected,
                "Unicode path filters preserve the full supported search length");
        Check(Database.Read(database, query with { Search = "escaped-alias.test" }, CancellationToken.None)
            .Rows.Count == 1, "Broad search preserves escaped JSON host keys and values");
        Check(Database.Read(database, query with
        {
            Search = "TCP",
            Conditions = [new(ObservationField.ServerName, FilterComparison.Equals, "SEARCHCHECK-default-transport")]
        }, CancellationToken.None).Rows.Count == 1, "JSON search preserves the default transport for missing fields");
        foreach (var text in new[] { "searchcheck-kelvin-δ-𐐨", "searchcheck-tail " })
            Check(Database.Read(database, query with
            {
                Search = text.TrimEnd(),
                Conditions = [new(ObservationField.ServerName, FilterComparison.NotEquals, text)]
            }, CancellationToken.None).Rows.Count == 0,
                "Literal exclusions use the same invariant equality as positive filters: " + text);
        Check(Database.Read(database, query with
        {
            Conditions =
            [new(ObservationField.Process, FilterComparison.NotEquals, "client.exe")]
        }, CancellationToken.None)
            .Rows.Count == 0, "A process exclusion does not match the alternate path or another endpoint owner");
        var endpointQuery = query with
        {
            FromUs = firstUs,
            ToUs = lastUs + 1000,
            Conditions =
            [new(ObservationField.Provider, FilterComparison.Equals, "investigation adapter"),
             new(ObservationField.ServerPort, FilterComparison.Equals, "443")]
        };
        var events = Insights.ReadEvents(database, endpointQuery, long.MaxValue,
            "\uffff", 0, CancellationToken.None).Rows;
        Check(events.Count == 250 && events.All(row => row.Provider == "Investigation adapter"),
            "Typed endpoint filters preserve bounded paging and interpret client/server socket roles");
        // Walk the exact final page without requesting an empty extra page.
        var endpointIds = new HashSet<string>();
        var beforeTime = long.MaxValue;
        var beforeId = "\uffff";
        var pageCount = 0;
        for (;;)
        {
            var page = Insights.ReadEvents(database, endpointQuery with { PageSize = 50 }, beforeTime,
                beforeId, 0, CancellationToken.None);
            Check(page.Rows.Count == 50 && page.Rows.All(row => endpointIds.Add(row.Id)),
                "Endpoint pages respect the selected size without duplicate cursor boundaries");
            ++pageCount;
            if (!page.HasMore)
                break;
            beforeTime = page.Rows[^1].TimestampUs;
            beforeId = page.Rows[^1].Id;
        }
        Check(pageCount == 8 && endpointIds.Count == 400, "The final full endpoint page has no next page");
        var serverQuery = endpointQuery with
        {
            Conditions = [.. endpointQuery.Conditions,
            new(ObservationField.ServerProcess, FilterComparison.Contains, "endpoint-Δ")]
        };
        Check(Insights.ReadEvents(database, serverQuery, long.MaxValue,
            "\uffff", 0, CancellationToken.None).Rows.Count == 200,
            "Server-side endpoint reports expose their process on the server role only");
        Check(Insights.ReadEvents(database, query with { Search = "ENDPOINT-δ" }, long.MaxValue, "\uffff", 0,
            CancellationToken.None).Rows.Count == 250,
            "Endpoint text search matches Unicode case across bounded pages");
        var unknownQuery = query with
        {
            Conditions = [new(ObservationField.ClientAddress,
            FilterComparison.NotObserved)]
        };
        Check(Insights.ReadEvents(database, unknownQuery, long.MaxValue,
            "\uffff", 0, CancellationToken.None).Rows.Count == 200,
            "Unknown endpoint roles do not manufacture client socket evidence");

        // Export complete populations even when a displayed page cursor would return no records.
        var reportQuery = query with { Before = new(0, 0) };
        var csv = Path.Combine(output, "connections.csv");
        Check(ReportExport.Write(database, reportQuery, ReportKind.Connections, csv, [], CancellationToken.None) == all,
            "Connection export includes every matching observation beyond the displayed page");
        using (var parser = new TextFieldParser(csv, Encoding.UTF8))
        {
            parser.SetDelimiters(",");
            parser.HasFieldsEnclosedInQuotes = true;
            var headings = parser.ReadFields()!;
            var index = Array.IndexOf(headings, "sni");
            var seen = new List<string>();
            while (!parser.EndOfData)
                seen.Add(parser.ReadFields()![index]);
            Check(seen.Count == all && seen.Contains("'=literal_%[x]'Δ\r\nsecond line"),
                "CSV preserves Unicode and multiline fields while neutralizing spreadsheet formulas");
        }
        var jsonl = Path.Combine(output, "endpoints.jsonl");
        Check(ReportExport.Write(database, endpointQuery,
            ReportKind.Endpoints, jsonl, [], CancellationToken.None) == 400 &&
            File.ReadLines(jsonl).All(line => JsonDocument.Parse(line).RootElement.GetProperty("provider")
                .GetString() == "Investigation adapter"),
                    "Endpoint JSONL export includes all matching pages and valid metadata");
        var policyFile = Path.Combine(output, "policies.jsonl");
        var policyCount = ReportExport.Write(database, query, ReportKind.Policies, policyFile,
            [new CryptoPolicy()], CancellationToken.None);
        Check(policyCount == all + 400 && File.ReadLines(policyFile).Select(line =>
            JsonDocument.Parse(line).RootElement.GetProperty("status").GetString()).ToHashSet()
                .SetEquals(["Pass", "Violation", "Insufficient evidence"]),
            "Policy export includes all outcomes and unmatched endpoint evidence " +
            "without counting matched reports twice");
        var existing = Path.Combine(output, "cancelled.csv");
        File.WriteAllText(existing, "Existing report");
        using (var cancellation = new CancellationTokenSource())
        {
            try
            {
                ReportExport.Write(database, query, ReportKind.Connections, existing, [], cancellation.Token,
                    new ProgressCallback(_ => cancellation.Cancel()));
                throw new InvalidOperationException("Cancelled report completed.");
            }
            catch (Exception error) when (cancellation.IsCancellationRequested &&
                error is OperationCanceledException or System.Data.Common.DbException)
            { }
        }
        Check(File.ReadAllText(existing) == "Existing report" && !Directory.EnumerateFiles(output, "*.tmp").Any(),
            "Cancelled export preserves an existing report and removes partial output");
        var empty = Path.Combine(output, "empty.csv");
        Check(ReportExport.Write(database, mismatch, ReportKind.Connections, empty, [], CancellationToken.None) == 0 &&
            File.ReadAllLines(empty).Length == 1, "An empty CSV export still has its complete column headings");
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        {
            result = "passed",
            checks,
            connections = all,
            endpoint_matches = 400,
            policy_assessments = policyCount
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Investigation: {checks.Count} checks passed.");
    }

    private static async Task VerifyConcurrentAnalyticsAsync(DatabaseSource source, string output,
        CancellationToken cancellation)
    {
        source = new(source.Provider, source.Provider == DatabaseProvider.SqlServer ?
            new SqlConnectionStringBuilder(source.ConnectionString) { Pooling = false }.ConnectionString :
            new NpgsqlConnectionStringBuilder(source.ConnectionString) { Pooling = false }.ConnectionString);
        using var writer = await source.OpenConnectionAsync(cancellation);
        using var command = writer.CreateCommand();
        var values = new Dictionary<string, object?>();
        command.CommandText = source.Provider == DatabaseProvider.SqlServer ?
            $"SELECT TOP(1) * FROM {source.Prefix}connections ORDER BY id" :
            $"SELECT * FROM {source.Prefix}connections ORDER BY id LIMIT 1";
        using (var reader = await command.ExecuteReaderAsync(cancellation))
        {
            if (!await reader.ReadAsync(cancellation))
                throw new InvalidOperationException("Analytics concurrency requires connection evidence.");
            for (var index = 0; index < reader.FieldCount; ++index)
                values[reader.GetName(index)] = reader.IsDBNull(index) ? null : reader.GetValue(index);
        }

        // Gate a JSON read while an external writer commits another connection between analytics queries.
        const int gateKey = 0x435A5A49;
        var gateFunction = source.Provider == DatabaseProvider.SqlServer ? """
            CREATE FUNCTION cipherazzi.analytics_gate(@document nvarchar(max)) RETURNS nvarchar(max)
            WITH INLINE=OFF AS
            BEGIN
                DECLARE @ready int;
                SELECT @ready=ready FROM cipherazzi.analytics_gate_control WITH (READCOMMITTEDLOCK) WHERE id=1;
                RETURN CASE WHEN @ready=1 THEN @document ELSE N'{}' END;
            END
            """ : $"""
            CREATE FUNCTION cipherazzi.analytics_gate(document text) RETURNS text LANGUAGE plpgsql VOLATILE AS $$
            BEGIN
                PERFORM pg_advisory_xact_lock({gateKey},1);
                RETURN document;
            END $$
            """;
        var setup = source.Provider == DatabaseProvider.SqlServer ? new[]
        {
            "CREATE TABLE cipherazzi.analytics_gate_control(id int PRIMARY KEY,ready int NOT NULL);" +
                "INSERT INTO cipherazzi.analytics_gate_control VALUES(1,1)",
            gateFunction,
            "EXEC sys.sp_rename N'cipherazzi.connections',N'analytics_evidence'"
        } : new[] { gateFunction, "ALTER TABLE cipherazzi.connections RENAME TO analytics_evidence" };
        foreach (var sql in setup)
        {
            command.CommandText = sql;
            await command.ExecuteNonQueryAsync(cancellation);
        }
        command.CommandText = "CREATE VIEW cipherazzi.connections AS SELECT " + string.Join(',', values.Keys
            .Select(name => name == "crypto_json" ? "cipherazzi.analytics_gate(c.crypto_json) AS crypto_json" :
                "c." + name)) + " FROM cipherazzi.analytics_evidence c";
        await command.ExecuteNonQueryAsync(cancellation);
        try
        {
            var query = new Query("", "", false, PageCursor.Newest);
            AnalyticsSnapshot Read() => Insights.ReadAnalytics(source, query, 0, "Group classification", 100,
                cancellation);
            object Counts(AnalyticsSnapshot snapshot) => new { total = snapshot.Total,
                protocols = snapshot.Protocols.Sum(row => row.Count), groups = snapshot.Groups.Sum(row => row.Count),
                breakdown = snapshot.Breakdown.Sum(row => row.Count),
                timeline = snapshot.Timeline.Sum(row => row.Count) };
            bool Consistent(AnalyticsSnapshot snapshot) => new[] { snapshot.Protocols, snapshot.Groups,
                snapshot.Breakdown }.All(rows => rows.Sum(row => row.Count) == snapshot.Total) &&
                snapshot.Timeline.Sum(row => row.Count) == snapshot.Total;
            var before = Read();
            using var gateConnection = await source.OpenConnectionAsync(cancellation);
            using var gate = await gateConnection.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted,
                cancellation);
            using var lockCommand = gateConnection.CreateCommand();
            lockCommand.Transaction = gate;
            lockCommand.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                "UPDATE cipherazzi.analytics_gate_control SET ready=2 WHERE id=1;SELECT @@SPID" :
                $"SELECT pg_advisory_xact_lock({gateKey},1);SELECT pg_backend_pid()";
            long gatePid;
            using (var reader = await lockCommand.ExecuteReaderAsync(cancellation))
            {
                if (source.Provider == DatabaseProvider.PostgreSql)
                    await reader.NextResultAsync(cancellation);
                await reader.ReadAsync(cancellation);
                gatePid = Convert.ToInt64(reader[0]);
            }
            var reading = Task.Run(Read, cancellation);
            var blocked = false;
            var canceled = false;
            double cancellationMs = 0;
            var application = "Cipherazzi analytics cancellation " + Guid.NewGuid().ToString("N");
            var tagged = source.Provider == DatabaseProvider.SqlServer ?
                new SqlConnectionStringBuilder(source.ConnectionString)
                { ApplicationName = application, Pooling = true }.ConnectionString :
                new NpgsqlConnectionStringBuilder(source.ConnectionString)
                { ApplicationName = application, Pooling = true }.ConnectionString;
            var recovery = new DatabaseSource(source.Provider, tagged);
            try
            {
                // Observe the held gate before committing the insert, avoiding scheduler-dependent stress loops.
                using var observer = await source.OpenConnectionAsync(cancellation);
                using var wait = observer.CreateCommand();
                wait.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                    "SELECT COUNT(*) FROM sys.dm_exec_requests WHERE blocking_session_id=@pid" :
                    "SELECT COUNT(*) FROM pg_stat_activity WHERE @pid=ANY(pg_blocking_pids(pid))";
                DatabaseSource.AddParameter(wait, "@pid", gatePid);
                var deadline = DateTime.UtcNow.AddSeconds(10);
                while (!reading.IsCompleted && DateTime.UtcNow < deadline)
                {
                    blocked = Convert.ToInt64(await wait.ExecuteScalarAsync(cancellation)) > 0;
                    if (blocked)
                        break;
                    await Task.Delay(25, cancellation);
                }
                if (!blocked)
                {
                    if (reading.IsCompleted)
                        await reading;
                    throw new InvalidOperationException("Analytics did not reach its query gate.");
                }

                // Cancel a second gated snapshot, then reuse its connection pool after ingestion resumes.
                using var stopping = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                var interrupted = Task.Run(() => Insights.ReadAnalytics(recovery, query, 0,
                    "Group classification", 100, stopping.Token), cancellation);
                try
                {
                    wait.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                        "SELECT count(*) FROM sys.dm_exec_sessions s JOIN sys.dm_exec_requests r " +
                        "ON r.session_id=s.session_id WHERE s.program_name=@application " +
                        "AND r.blocking_session_id<>0" :
                        "SELECT count(*) FROM pg_stat_activity WHERE application_name=@application " +
                        "AND wait_event_type='Lock'";
                    wait.Parameters.Clear();
                    DatabaseSource.AddParameter(wait, "@application", application);
                    deadline = DateTime.UtcNow.AddSeconds(5);
                    var waiting = false;
                    while (!interrupted.IsCompleted && DateTime.UtcNow < deadline)
                    {
                        waiting = Convert.ToInt64(await wait.ExecuteScalarAsync(cancellation)) > 0;
                        if (waiting)
                            break;
                        await Task.Delay(25, cancellation);
                    }
                    if (!waiting)
                    {
                        if (interrupted.IsCompleted)
                            await interrupted;
                        throw new InvalidOperationException("Analytics cancellation did not reach its query gate.");
                    }
                    var watch = System.Diagnostics.Stopwatch.StartNew();
                    stopping.Cancel();
                    try { await interrupted.WaitAsync(TimeSpan.FromSeconds(3), cancellation); }
                    catch (OperationCanceledException) when (stopping.IsCancellationRequested) { canceled = true; }
                    catch (SqlException error) when (error.Number == 0 && stopping.IsCancellationRequested)
                    { canceled = true; }
                    catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.QueryCanceled &&
                        stopping.IsCancellationRequested) { canceled = true; }
                    cancellationMs = watch.Elapsed.TotalMilliseconds;
                    if (!canceled)
                        throw new InvalidOperationException("A gated analytics query ignored cancellation.");
                }
                finally
                {
                    stopping.Cancel();
                    if (!interrupted.IsCompleted)
                    {
                        try { await interrupted.WaitAsync(TimeSpan.FromSeconds(3)); }
                        catch (OperationCanceledException) { }
                        catch (SqlException error) when (error.Number == 0) { }
                        catch (PostgresException error) when (error.SqlState == PostgresErrorCodes.QueryCanceled) { }
                    }
                }
                values.Remove("id");
                values["flow_id"] = 987654323L;
                using var transaction = await writer.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted,
                    cancellation);
                command.Transaction = transaction;
                command.CommandText = "UPDATE cipherazzi.metadata SET revision=revision+1," +
                    "observation_revision=revision+1 WHERE id=1;";
                await command.ExecuteNonQueryAsync(cancellation);
                command.CommandText = "INSERT INTO cipherazzi.analytics_evidence(" + string.Join(',', values.Keys) +
                    ") VALUES(" + string.Join(',', values.Keys.Select((_, index) => "@value" + index)) + ")";
                var parameter = 0;
                foreach (var value in values.Values)
                    DatabaseSource.AddParameter(command, "@value" + parameter++, value ?? DBNull.Value);
                await command.ExecuteNonQueryAsync(cancellation);
                await transaction.CommitAsync(cancellation);
                command.Transaction = null;
            }
            finally { await gate.RollbackAsync(CancellationToken.None); }
            var during = await reading.WaitAsync(TimeSpan.FromSeconds(15), cancellation);
            var after = Insights.ReadAnalytics(recovery, query, 0, "Group classification", 100, cancellation);
            File.WriteAllText(Path.Combine(output, "analytics-concurrent.json"), JsonSerializer.Serialize(new
            {
                before = Counts(before), during = Counts(during), after = Counts(after), blocked, canceled,
                cancellation_ms = cancellationMs, pooled_recovery = true
            }));
            if (!Consistent(before) || !Consistent(during) || !Consistent(after) ||
                during.Total != before.Total || after.Total != before.Total + 1)
                throw new InvalidOperationException("Analytics mixed its summary and chart snapshots.");
            Console.WriteLine("Concurrent analytics snapshot passed.");
        }
        finally
        {
            // Restore the ordinary table before exercising other production readers and writers.
            command.Transaction = null;
            command.Parameters.Clear();
            command.CommandText = source.Provider == DatabaseProvider.SqlServer ? """
                DROP VIEW cipherazzi.connections;
                EXEC sys.sp_rename N'cipherazzi.analytics_evidence',N'connections';
                DROP FUNCTION cipherazzi.analytics_gate;
                DROP TABLE cipherazzi.analytics_gate_control;
                """ : """
                DROP VIEW cipherazzi.connections;
                ALTER TABLE cipherazzi.analytics_evidence RENAME TO connections;
                DROP FUNCTION cipherazzi.analytics_gate(text);
                """;
            await command.ExecuteNonQueryAsync(CancellationToken.None);
        }
    }

    private static async Task VerifyConcurrentReadinessAsync(DatabaseSource source, string output,
        CancellationToken cancellation)
    {
        source = new(source.Provider, source.Provider == DatabaseProvider.SqlServer ?
            new SqlConnectionStringBuilder(source.ConnectionString) { Pooling = false }.ConnectionString :
            new NpgsqlConnectionStringBuilder(source.ConnectionString) { Pooling = false }.ConnectionString);
        var query = new Query("", "", false, PageCursor.Newest);
        PqcSnapshot Read() => PqcInsights.Read(source, query, 0, long.MaxValue,
            "Client application", [new()], cancellation);
        using var writer = await source.OpenConnectionAsync(cancellation);
        var values = new Dictionary<string, object?>();
        using (var command = writer.CreateCommand())
        {
            command.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                $"SELECT TOP(1) * FROM {source.Prefix}connections ORDER BY id" :
                $"SELECT * FROM {source.Prefix}connections ORDER BY id LIMIT 1";
            using var reader = await command.ExecuteReaderAsync(cancellation);
            if (!await reader.ReadAsync(cancellation))
                throw new InvalidOperationException("Readiness concurrency requires connection evidence.");
            for (var index = 0; index < reader.FieldCount; ++index)
                values[reader.GetName(index)] = reader.IsDBNull(index) ? null : reader.GetValue(index);
        }
        values.Remove("id");
        values["flow_id"] = 987654322L;
        using (var command = writer.CreateCommand())
        {
            command.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                $"SELECT TOP(1) id,detail_json FROM {source.Prefix}endpoint_events ORDER BY id" :
                $"SELECT id,detail_json FROM {source.Prefix}endpoint_events ORDER BY id LIMIT 1";
            string id, json;
            using (var reader = await command.ExecuteReaderAsync(cancellation))
            {
                if (!await reader.ReadAsync(cancellation))
                    throw new InvalidOperationException("Readiness concurrency requires endpoint evidence.");
                id = reader.GetString(0);
                json = reader.GetString(1);
            }
            var detail = System.Text.Json.Nodes.JsonNode.Parse(json)!.AsObject();
            detail["matched_run_id"] = values["run_id"]!.ToString();
            detail["matched_flow_id"] = 987654322L;
            command.CommandText = $"UPDATE {source.Prefix}endpoint_events SET detail_json=@detail WHERE id=@id";
            DatabaseSource.AddParameter(command, "@detail", detail.ToJsonString());
            DatabaseSource.AddParameter(command, "@id", id);
            await command.ExecuteNonQueryAsync(cancellation);
        }
        var before = Read();

        // Hold endpoint query compilation after packet aggregation, then create its previously absent match.
        using var gateConnection = await source.OpenConnectionAsync(cancellation);
        using var gate = await gateConnection.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted,
            cancellation);
        using (var command = gateConnection.CreateCommand())
        {
            command.Transaction = gate;
            command.CommandText = $"ALTER TABLE {source.Prefix}endpoint_events ADD readiness_gate_probe bigint NULL";
            await command.ExecuteNonQueryAsync(cancellation);
        }
        var reading = Task.Run(Read, cancellation);
        var blocked = false;
        try
        {
            using var observer = await source.OpenConnectionAsync(cancellation);
            using var command = observer.CreateCommand();
            command.CommandText = source.Provider == DatabaseProvider.SqlServer ? """
                SELECT COUNT(*) FROM sys.dm_exec_requests r CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
                WHERE r.database_id=DB_ID() AND r.session_id<>@@SPID AND r.wait_type IN ('LCK_M_SCH_S','LCK_M_IS')
                    AND t.text LIKE '%endpoint_events%'
                """ : """
                SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
                    AND wait_event_type='Lock' AND query LIKE '%endpoint_events%'
                """;
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!reading.IsCompleted && DateTime.UtcNow < deadline)
            {
                blocked = Convert.ToInt64(await command.ExecuteScalarAsync(cancellation)) > 0;
                if (blocked)
                    break;
                await Task.Delay(25, cancellation);
            }
            if (!blocked)
            {
                if (reading.IsCompleted)
                    await reading;
                command.CommandText = source.Provider == DatabaseProvider.SqlServer ? """
                    SELECT r.wait_type,t.text FROM sys.dm_exec_requests r
                        CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
                    WHERE r.database_id=DB_ID() AND r.session_id<>@@SPID
                    """ : """
                    SELECT wait_event,query FROM pg_stat_activity
                    WHERE datname=current_database() AND pid<>pg_backend_pid()
                    """;
                var waits = new List<object>();
                using (var reader = await command.ExecuteReaderAsync(cancellation))
                    while (await reader.ReadAsync(cancellation))
                        waits.Add(new { wait = reader[0].ToString(), query = reader[1].ToString() });
                File.WriteAllText(Path.Combine(output, "readiness-gate-waits.json"), JsonSerializer.Serialize(waits));
                throw new InvalidOperationException("Readiness did not reach the endpoint query gate.");
            }
            using var transaction = await writer.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted,
                cancellation);
            using var insert = writer.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = $"UPDATE {source.Prefix}metadata SET revision=revision+1," +
                "observation_revision=revision+1 WHERE id=1;";
            await insert.ExecuteNonQueryAsync(cancellation);
            insert.CommandText = $"INSERT INTO {source.Prefix}connections(" + string.Join(',', values.Keys) +
                ") VALUES(" + string.Join(',', values.Keys.Select((_, index) => "@value" + index)) + ")";
            var parameter = 0;
            foreach (var value in values.Values)
                DatabaseSource.AddParameter(insert, "@value" + parameter++, value ?? DBNull.Value);
            await insert.ExecuteNonQueryAsync(cancellation);
            await transaction.CommitAsync(cancellation);
        }
        finally
        {
            await gate.RollbackAsync(CancellationToken.None);
        }
        var during = await reading.WaitAsync(TimeSpan.FromSeconds(15), cancellation);
        var after = Read();
        File.WriteAllText(Path.Combine(output, "readiness-concurrent.json"), JsonSerializer.Serialize(new
        { before = before.Total, during = during.Total, after = after.Total, before_revision = before.Revision,
            during_revision = during.Revision, after_revision = after.Revision, blocked }));
        if (before.Total != during.Total || before.Total != after.Total || during.Revision != before.Revision)
            throw new InvalidOperationException($"Readiness mixed concurrent states: before={before.Total}, " +
                $"during={during.Total}, after={after.Total}.");
        Console.WriteLine("Concurrent readiness snapshot passed.");
    }

    private static async Task VerifyConcurrentExportAsync(DatabaseSource source, string output)
    {
        var query = new Query("", "", false, PageCursor.Newest);
        var policies = new[] { new CryptoPolicy() };
        var before = ReportExport.Write(source, query, ReportKind.Policies,
            Path.Combine(output, "before-concurrent.jsonl"), policies, CancellationToken.None);
        var connectionValues = new Dictionary<string, object?>();
        var endpointValues = new Dictionary<string, object?>();
        using (var connection = await source.OpenConnectionAsync(CancellationToken.None))
        {
            foreach (var (table, values) in new[] { ("connections",
                connectionValues), ("endpoint_events", endpointValues) })
            {
                using var command = connection.CreateCommand();
                command.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                    $"SELECT TOP(1) * FROM {source.Prefix}{table} ORDER BY id" :
                    $"SELECT * FROM {source.Prefix}{table} ORDER BY id LIMIT 1";
                using var reader = await command.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                    throw new InvalidOperationException(
                        "Concurrent export requires populated connection and endpoint evidence.");
                for (var index = 0; index < reader.FieldCount; index++)
                    values[reader.GetName(index)] = reader.IsDBNull(index) ? null : reader.GetValue(index);
            }
        }
        connectionValues.Remove("id");
        connectionValues["flow_id"] = 987654321L;
        connectionValues["first_us"] = Convert.ToInt64(connectionValues["first_us"]) - 1000;
        endpointValues["id"] = "concurrent-" + Guid.NewGuid().ToString("N");
        var detail = System.Text.Json.Nodes.JsonNode.Parse(endpointValues["detail_json"]!.ToString()!)!.AsObject();
        detail.Remove("matched_run_id");
        detail.Remove("matched_flow_id");
        endpointValues["detail_json"] = detail.ToJsonString();
        Task? mutation = null;
        async Task InsertAsync()
        {
            using var connection = await source.OpenConnectionAsync(CancellationToken.None);
            using var transaction = await connection.BeginTransactionAsync();
            foreach (var (table, values) in new[] { ("connections",
                connectionValues), ("endpoint_events", endpointValues) })
            {
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandTimeout = 30;
                command.CommandText = $"INSERT INTO {source.Prefix}{table}(" + string.Join(',', values.Keys) +
                    ") VALUES(" + string.Join(',', values.Keys.Select((_, index) => "@value" + index)) + ")";
                var index = 0;
                foreach (var value in values.Values)
                    DatabaseSource.AddParameter(command, "@value" + index++, value ?? DBNull.Value);
                await command.ExecuteNonQueryAsync();
            }
            await transaction.CommitAsync();
        }

        // Commit a connection and unmatched endpoint together after the connection reader has passed their position.
        var during = ReportExport.Write(source, query, ReportKind.Policies,
            Path.Combine(output, "during-concurrent.jsonl"), policies, CancellationToken.None,
            new ProgressCallback(_ =>
            {
                if (mutation is not null)
                    return;
                mutation = Task.Run(InsertAsync);
                Task.WhenAny(mutation, Task.Delay(1000)).GetAwaiter().GetResult();
            }));
        if (mutation is null)
            throw new InvalidOperationException("Concurrent export did not start its writer.");
        await mutation;
        var after = ReportExport.Write(source, query, ReportKind.Policies,
            Path.Combine(output, "after-concurrent.jsonl"), policies, CancellationToken.None);
        if (after != before + 2 || during != before && during != after)
            throw new InvalidOperationException($"Export mixed concurrent database states: before={before}, " +
                $"during={during}, after={after}.");
        File.WriteAllText(Path.Combine(output, "concurrent-results.json"), JsonSerializer.Serialize(new
        {
            result = "passed",
            before,
            during,
            after,
            snapshot = true
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Concurrent export snapshot passed.");
    }
}
