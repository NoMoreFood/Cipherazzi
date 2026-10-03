using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

internal static class ReplicationMemory
{
    public static async Task RunAsync(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var target = DatabaseSource.FromEnvironment(args[2], "CIPHERAZZI_CONNECTION");
        var database = target.Provider == DatabaseProvider.SqlServer ?
            new SqlConnectionStringBuilder(target.ConnectionString).InitialCatalog :
            new NpgsqlConnectionStringBuilder(target.ConnectionString).Database;
        if (database?.StartsWith("CipherazziReplicationMemory_", StringComparison.Ordinal) != true)
            throw new InvalidOperationException("Use an isolated CipherazziReplicationMemory_ database.");
        if (!args.Contains("--child"))
        {
            // Apply a real heap limit in a separate process, including provider initialization and fixture setup.
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Test host unavailable.");
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
            foreach (var argument in new[] { "--replication-memory" }.Concat(args).Append("--child"))
                start.ArgumentList.Add(argument);
            start.Environment["DOTNET_GCHeapHardLimit"] = "0x10000000";
            using var child = Process.Start(start)!;
            var stdout = child.StandardOutput.ReadToEndAsync();
            var stderr = child.StandardError.ReadToEndAsync();
            try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(6)); }
            finally
            {
                if (!child.HasExited)
                    child.Kill(entireProcessTree: true);
            }
            File.WriteAllText(Path.Combine(output, "child.stdout"), await stdout);
            File.WriteAllText(Path.Combine(output, "child.stderr"), await stderr);
            if (child.ExitCode != 0)
                throw new InvalidOperationException("The bounded relay test failed. See its child output.");
            Console.WriteLine("Large revision replication passed within a 256 MiB managed heap.");
            return;
        }

        // A bulk ownership correction can place a journal's complete connection history in one revision.
        var path = Path.Combine(output, "source.db");
        using (var input = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var fixture = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            input.Open();
            fixture.Open();
            input.BackupDatabase(fixture);
            using var command = fixture.CreateCommand();
            command.CommandText = """
                PRAGMA foreign_keys=OFF;
                DELETE FROM endpoint_certificates;
                DELETE FROM endpoint_events;
                DELETE FROM connection_certificates;
                DELETE FROM connections WHERE id<>(SELECT min(id) FROM connections);
                SELECT crypto_json FROM connections;
                """;
            var json = Convert.ToString(command.ExecuteScalar()) ??
                throw new InvalidOperationException("A connection seed is required.");
            if (json.Length < 3072)
            {
                var evidence = JsonNode.Parse(json)!.AsObject();
                evidence["replication_fixture"] = new string('x', 3072);
                json = evidence.ToJsonString();
            }
            command.CommandText = "PRAGMA table_info(connections)";
            var columns = new List<string>();
            using (var reader = command.ExecuteReader())
                while (reader.Read())
                    if (reader.GetString(1) != "id")
                        columns.Add(reader.GetString(1));
            command.CommandText = """
                UPDATE connections SET crypto_json=@json,
                    source_pid=NULL,source_process='',source_path='',source_process_started_us=NULL,
                    source_evidence='',source_account='',source_account_domain='',source_account_sid='',
                    destination_pid=NULL,destination_process='',destination_path='',destination_process_started_us=NULL,
                    destination_evidence='',destination_account='',destination_account_domain='',
                    destination_account_sid='';
                """;
            command.Parameters.AddWithValue("@json", json);
            command.ExecuteNonQuery();
            command.Parameters.Clear();
            command.CommandText = "WITH RECURSIVE rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM rows WHERE n<99999) " +
                "INSERT INTO connections(" + string.Join(',', columns) + ") SELECT " +
                string.Join(',', columns.Select(column => column switch
                {
                    "flow_id" => "c.flow_id+n", "first_us" => "c.first_us+n*2000",
                    "last_us" => "c.last_us+n*2000", _ => "c." + column
                })) + " FROM connections c CROSS JOIN rows";
            command.ExecuteNonQuery();
            command.CommandText = """
                UPDATE metadata SET database_id=lower(hex(randomblob(16))),revision=revision+1,
                    observation_revision=revision+1;
                """;
            command.ExecuteNonQuery();
            foreach (var table in new[] { "capture_sessions", "connections", "certificates" })
            {
                command.CommandText = $"UPDATE {table} SET change_revision=(SELECT revision FROM metadata)";
                command.ExecuteNonQuery();
            }
        }
        var source = DatabaseSource.Sqlite(path);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        await Replication.InitializeAsync(target, cancellation.Token);
        var watch = Stopwatch.StartNew();
        var batch = await Replication.SyncAsync(path, target, cancellation.Token);
        var uploadMs = watch.Elapsed.TotalMilliseconds;

        // Compare complete records and dependencies after the single atomic publication and acknowledgement.
        var localHash = StressConnectivity.Fingerprint(source);
        var remoteHash = StressConnectivity.Fingerprint(target);
        using var remote = await target.OpenConnectionAsync(cancellation.Token);
        using var status = remote.CreateCommand();
        status.CommandText = "SELECT revision FROM cipherazzi.replication_sources";
        var cursor = Convert.ToInt64(await status.ExecuteScalarAsync(cancellation.Token));
        status.CommandText = "SELECT observation_revision FROM cipherazzi.metadata WHERE id=1";
        var stamp = Convert.ToInt64(await status.ExecuteScalarAsync(cancellation.Token));
        using var local = await source.OpenConnectionAsync(cancellation.Token);
        using var acknowledgement = local.CreateCommand();
        acknowledgement.CommandText =
            "SELECT count(*) FROM replication_consumers WHERE acknowledged_revision=@revision";
        DatabaseSource.AddParameter(acknowledgement, "@revision", batch.Revision);
        var acknowledged = Convert.ToInt64(await acknowledgement.ExecuteScalarAsync(cancellation.Token)) > 0;
        var memory = GC.GetGCMemoryInfo();
        var peak = Process.GetCurrentProcess().PeakWorkingSet64;
        var passed = batch.Connections == 100000 && !batch.More && cursor == batch.Revision && stamp > 0 &&
            acknowledged && localHash == remoteHash && memory.TotalAvailableMemoryBytes <= 256L * 1024 * 1024 &&
            peak < 256L * 1024 * 1024;
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        {
            passed, observations = batch.Connections, upload_ms = uploadMs, peak_working_set_bytes = peak,
            managed_heap_bytes = memory.HeapSizeBytes, managed_limit_bytes = memory.TotalAvailableMemoryBytes,
            acknowledged, cursor, source_revision = batch.Revision, observation_revision = stamp,
            exact_records_and_dependencies = localHash == remoteHash, fingerprint = remoteHash
        }, new JsonSerializerOptions { WriteIndented = true }));
        if (!passed)
            throw new InvalidOperationException(
                "Large revision replication exceeded its memory bound or changed evidence.");
    }
}
