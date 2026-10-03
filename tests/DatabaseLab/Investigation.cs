using System.Text;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.VisualBasic.FileIO;
using Npgsql;

internal static class Investigation
{
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
                    ["role"] = unknown ? "unknown" : server ? "server" : "client", ["transport"] = "TCP",
                    ["local"] = new { address = server ? "192.0.2.2" : "192.0.2.1", port = server ? 443 : 45000 },
                    ["remote"] = new { address = server ? "192.0.2.1" : "192.0.2.2", port = server ? 45000 : 443 },
                    ["assessment"] = new
                    {
                        first_us = first + index, last_us = first + index + 500, tls_version = 772,
                        local_role = unknown ? "Unknown" : server ? "Server" : "Client", process = "endpoint-Δ.exe",
                        path = "C:/Lab/endpoint-Δ.exe", server_name = "endpoint.test", server_port = 443,
                        group_name = "X25519", key_exchange = "ECDHE", authentication = "", certificate_facts = "",
                        crypto = new { protocol = "TLS", transport = "TCP", evidence_source = "Endpoint",
                            group_class = "Classical", endpoint_confirmations = new[] { new { success = true,
                                local_role = server ? "Server" : "Client", peer_verified = 1 } } }
                    }
                };
                if (index % 3 == 0)
                {
                    detail["matched_run_id"] = run;
                    detail["matched_flow_id"] = flow;
                }
                command.Parameters.Clear();
                command.CommandText = """
                    INSERT INTO endpoint_events(id,run_id,timestamp_us,provider,kind,result,pid,peer,port,protocol,cipher,
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
            File.WriteAllText(Path.Combine(output, "bounds.json"), JsonSerializer.Serialize(new { first, last, total }));
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
            // Replicate the same capture evidence into a fresh server database, then use production readers and exports.
            await Replication.InitializeAsync(target, deadline.Token);
            while ((await Replication.SyncAsync(args[0], target, deadline.Token)).More) {}
            Verify(target, output);
            await VerifyConcurrentExportAsync(target, output);
            File.WriteAllText(Path.Combine(output, "server.json"), JsonSerializer.Serialize(new
            {
                provider = target.Provider.ToString(), version = connection.ServerVersion,
                database = name, isolated = true
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
        var scoped = query with { FromUs = firstUs, ToUs = lastUs, Conditions =
            [new(ObservationField.ServerName, FilterComparison.Equals, "CASE-1.MIGRATION.TEST"),
             new(ObservationField.ClientProcess, FilterComparison.Contains, "CLIENT"),
             new(ObservationField.ServerPort, FilterComparison.Equals, "443")] };
        var rows = Database.Read(database, scoped, CancellationToken.None);
        Check(rows.Rows.Count == all / 10 && rows.Rows.All(row => row.Value("Sni") == "case-1.migration.test"),
            "Date and typed conditions intersect across the full observation scope");
        var analytics = Insights.ReadAnalytics(database, scoped, lastUs + 1, "Protocol", 20, CancellationToken.None);
        Check(analytics.Total == all / 10, "Explicit dates replace an analytics preset outside the chosen range");
        var readiness = PqcInsights.Read(database, scoped, lastUs + 1, lastUs + 2, "Client application",
            [new CryptoPolicy()], CancellationToken.None);
        Check(readiness.Total == all / 10 && readiness.PolicyObservations == all / 10,
            "Readiness and policy evaluation use the same date and field conditions as connections");
        var mismatch = scoped with { Conditions = [.. scoped.Conditions,
            new(ObservationField.KeyClass, FilterComparison.Equals, "Classical")] };
        Check(Database.Read(database, mismatch, CancellationToken.None).Rows.Count == 0,
            "An additional contradictory field condition cannot widen the scope");
        var literal = query with { Conditions = [new(ObservationField.ServerName, FilterComparison.Contains, "_%[x]'")] };
        Check(Database.Read(database, literal, CancellationToken.None).Rows.Count == 1,
            "Filter values containing quotes and SQL wildcard punctuation remain literal");
        Check(Database.Read(database, query with { Search = "_%[x]'δ" }, CancellationToken.None).Rows.Count == 1,
            "Text search applies Unicode case matching while preserving literal wildcard punctuation");
        Check(Database.Read(database, query with { Conditions =
            [new(ObservationField.Process, FilterComparison.NotEquals, "client.exe")] }, CancellationToken.None)
            .Rows.Count == 0, "A process exclusion does not match the alternate path or another endpoint owner");
        var endpointQuery = query with { FromUs = firstUs, ToUs = lastUs + 1000, Conditions =
            [new(ObservationField.Provider, FilterComparison.Equals, "investigation adapter"),
             new(ObservationField.ServerPort, FilterComparison.Equals, "443")] };
        var events = Insights.ReadEvents(database, endpointQuery, long.MaxValue, "\uffff", 0, CancellationToken.None);
        Check(events.Count == 250 && events.All(row => row.Provider == "Investigation adapter"),
            "Typed endpoint filters preserve bounded paging and interpret client/server socket roles");
        var serverQuery = endpointQuery with { Conditions = [.. endpointQuery.Conditions,
            new(ObservationField.ServerProcess, FilterComparison.Contains, "endpoint-Δ")] };
        Check(Insights.ReadEvents(database, serverQuery, long.MaxValue, "\uffff", 0, CancellationToken.None).Count == 200,
            "Server-side endpoint reports expose their process on the server role only");
        Check(Insights.ReadEvents(database, query with { Search = "ENDPOINT-δ" }, long.MaxValue, "\uffff", 0,
            CancellationToken.None).Count == 250, "Endpoint text search matches Unicode case across bounded pages");
        var unknownQuery = query with { Conditions = [new(ObservationField.ClientAddress, FilterComparison.NotObserved)] };
        Check(Insights.ReadEvents(database, unknownQuery, long.MaxValue, "\uffff", 0, CancellationToken.None).Count == 200,
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
        Check(ReportExport.Write(database, endpointQuery, ReportKind.Endpoints, jsonl, [], CancellationToken.None) == 400 &&
            File.ReadLines(jsonl).All(line => JsonDocument.Parse(line).RootElement.GetProperty("provider")
                .GetString() == "Investigation adapter"), "Endpoint JSONL export includes all matching pages and valid metadata");
        var policyFile = Path.Combine(output, "policies.jsonl");
        var policyCount = ReportExport.Write(database, query, ReportKind.Policies, policyFile,
            [new CryptoPolicy()], CancellationToken.None);
        Check(policyCount == all + 400 && File.ReadLines(policyFile).Select(line =>
            JsonDocument.Parse(line).RootElement.GetProperty("status").GetString()).ToHashSet()
                .SetEquals(["Pass", "Violation", "Insufficient evidence"]),
            "Policy export includes all outcomes and unmatched endpoint evidence without counting matched reports twice");
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
                error is OperationCanceledException or System.Data.Common.DbException) {}
        }
        Check(File.ReadAllText(existing) == "Existing report" && !Directory.EnumerateFiles(output, "*.tmp").Any(),
            "Cancelled export preserves an existing report and removes partial output");
        var empty = Path.Combine(output, "empty.csv");
        Check(ReportExport.Write(database, mismatch, ReportKind.Connections, empty, [], CancellationToken.None) == 0 &&
            File.ReadAllLines(empty).Length == 1, "An empty CSV export still has its complete column headings");
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        {
            result = "passed", checks, connections = all, endpoint_matches = 400, policy_assessments = policyCount
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Investigation: {checks.Count} checks passed.");
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
            foreach (var (table, values) in new[] { ("connections", connectionValues), ("endpoint_events", endpointValues) })
            {
                using var command = connection.CreateCommand();
                command.CommandText = source.Provider == DatabaseProvider.SqlServer ?
                    $"SELECT TOP(1) * FROM {source.Prefix}{table} ORDER BY id" :
                    $"SELECT * FROM {source.Prefix}{table} ORDER BY id LIMIT 1";
                using var reader = await command.ExecuteReaderAsync();
                if (!await reader.ReadAsync())
                    throw new InvalidOperationException("Concurrent export requires populated connection and endpoint evidence.");
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
            foreach (var (table, values) in new[] { ("connections", connectionValues), ("endpoint_events", endpointValues) })
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
            result = "passed", before, during, after, snapshot = true
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Concurrent export snapshot passed.");
    }
}
