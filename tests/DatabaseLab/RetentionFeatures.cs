using System.Data.Common;
using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class RetentionFeatures
{
    public static async Task RunAsync(string[] args)
    {
        var directory = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "retention.db");
        var prefix = "retention" + Guid.NewGuid().ToString("N");
        using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var destination = new SqliteConnection($"Data Source={path}"))
        {
            source.Open();
            destination.Open();
            source.BackupDatabase(destination);
            using var command = destination.CreateCommand();
            command.CommandText = """
                PRAGMA foreign_keys=OFF;
                PRAGMA journal_mode=DELETE;
                BEGIN IMMEDIATE;
                UPDATE metadata SET database_id=lower(hex(randomblob(16))),revision=revision+1;
                UPDATE capture_sessions SET id=@prefix||id,started_us=1,stopped_us=2,
                    change_revision=(SELECT revision FROM metadata);
                UPDATE connections SET run_id=@prefix||run_id,first_us=1,last_us=2,ended_us=2,
                    change_revision=(SELECT revision FROM metadata);
                UPDATE connection_certificates SET run_id=@prefix||run_id,
                    change_revision=(SELECT revision FROM metadata);
                UPDATE certificates SET change_revision=(SELECT revision FROM metadata);
                UPDATE endpoint_events SET run_id=@prefix||run_id,timestamp_us=2,
                    change_revision=(SELECT revision FROM metadata);
                CREATE TABLE IF NOT EXISTS replication_consumers(target_id TEXT PRIMARY KEY,
                    acknowledged_revision INTEGER NOT NULL CHECK(acknowledged_revision>=0),
                    updated_us INTEGER NOT NULL) STRICT;
                DELETE FROM replication_consumers;
                COMMIT;
                """;
            command.Parameters.AddWithValue("@prefix", prefix);
            command.ExecuteNonQuery();
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var targets = new[]
        {
            DatabaseSource.FromEnvironment("sqlserver", "CIPHERAZZI_SQLSERVER"),
            DatabaseSource.FromEnvironment("postgresql", "CIPHERAZZI_POSTGRESQL")
        };
        var adminTargets = new List<(DatabaseSource Target, string Name)>();
        try
        {
            for (var index = 0; index < targets.Length; ++index)
            {
                var target = targets[index];
                var name = "CipherazziRetention_" + Guid.NewGuid().ToString("N")[..10];
                var builder = target.Provider == DatabaseProvider.SqlServer ? (DbConnectionStringBuilder)
                    new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(target.ConnectionString) :
                    new Npgsql.NpgsqlConnectionStringBuilder(target.ConnectionString);
                var databaseKey = target.Provider == DatabaseProvider.SqlServer ? "Initial Catalog" : "Database";
                builder[databaseKey] = target.Provider == DatabaseProvider.SqlServer ? "master" : "postgres";
                var admin = new DatabaseSource(target.Provider, builder.ConnectionString);
                using var server = await admin.OpenConnectionAsync(deadline.Token);
                using var command = server.CreateCommand();
                command.CommandText = target.Provider == DatabaseProvider.SqlServer ?
                    $"CREATE DATABASE [{name}]" : $"CREATE DATABASE \"{name}\"";
                await command.ExecuteNonQueryAsync(deadline.Token);
                adminTargets.Add((admin, name));
                builder[databaseKey] = name;
                targets[index] = new(target.Provider, builder.ConnectionString);
            }
            long Local(string sql)
            {
                using var connection = new SqliteConnection($"Data Source={path}");
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = sql;
                return Convert.ToInt64(command.ExecuteScalar());
            }
            void Modify(string sql) => Local(sql + "; SELECT 0;");
            void Require(bool result, string message)
            {
                if (!result) throw new InvalidOperationException(message);
            }
            var count = Local("SELECT count(*) FROM connections");
            var available = Local("SELECT revision FROM metadata");
            foreach (var target in targets)
            {
                await Replication.InitializeAsync(target, deadline.Token);
                using var destination = await target.OpenConnectionAsync(deadline.Token);
                using var command = destination.CreateCommand();
                var constraint = "retention_" + Guid.NewGuid().ToString("N");
                command.CommandText = $"ALTER TABLE cipherazzi.connections ADD CONSTRAINT {constraint} " +
                    $"CHECK(run_id NOT LIKE '{prefix}%')";
                await command.ExecuteNonQueryAsync(deadline.Token);
                try
                {
                    bool failed = false;
                    try { await Replication.SyncAsync(path, target, deadline.Token); }
                    catch (DbException) { failed = true; }
                    Require(failed, "The destination rejection did not abort replication.");
                    Require(Local("SELECT min(acknowledged_revision) FROM replication_consumers") == 0,
                        "The failed destination advanced its acknowledgement.");
                    command.CommandText = $"SELECT count(*) FROM cipherazzi.capture_sessions WHERE id LIKE '{prefix}%'";
                    Require(Convert.ToInt64(await command.ExecuteScalarAsync(deadline.Token)) == 0,
                        "The failed server transaction partially published a capture session.");
                    Require(Local("SELECT max(acknowledged_revision) FROM replication_consumers") ==
                        (target.Provider == DatabaseProvider.SqlServer ? 0 : available),
                        "A failed server transaction acknowledged unpublished metadata.");
                }
                finally
                {
                    command.CommandText = $"ALTER TABLE cipherazzi.connections DROP CONSTRAINT {constraint}";
                    await command.ExecuteNonQueryAsync(CancellationToken.None);
                }
                async Task CatchUp()
                {
                    while ((await Replication.SyncAsync(path, target, deadline.Token)).More) {}
                }
                await Task.WhenAll(CatchUp(), CatchUp());
            }
            Require(Local("SELECT count(*) FROM replication_consumers WHERE acknowledged_revision=" + available) == 2,
                "All destinations did not acknowledge the committed source revision.");
            Modify("INSERT INTO replication_consumers VALUES('offline',0,0)");
            var emptyCapture = Path.Combine(directory, "empty.pcap");
            File.WriteAllBytes(emptyCapture, [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0]);
            async Task Maintain()
            {
                var info = new ProcessStartInfo(Path.GetFullPath(args[2]))
                {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                foreach (var value in new[] { "--db", path, "--replay", emptyCapture, "--retention-days", "1",
                    "--retention-mb", "0", "--replication-required" }) info.ArgumentList.Add(value);
                using var process = Process.Start(info)!;
                var output = process.StandardOutput.ReadToEndAsync();
                var error = process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync(deadline.Token);
                Require(process.ExitCode == 0, "Collector retention failed: " + await error);
                await output;
            }
            await Maintain();
            Require(Local("SELECT count(*) FROM connections") == count, "An offline consumer lost retained data.");
            Modify("DELETE FROM replication_consumers WHERE target_id='offline'");
            await Maintain();
            Require(Local("SELECT count(*) FROM connections") == 0,
                "Acknowledged expired observations were not pruned.");
            Require(Local("SELECT count(*) FROM pragma_foreign_key_check") == 0, "Retention violated foreign keys.");
            foreach (var target in targets)
            {
                using var connection = await target.OpenConnectionAsync(deadline.Token);
                using var command = connection.CreateCommand();
                command.CommandText = "SELECT count(*) FROM cipherazzi.connections WHERE run_id LIKE @prefix";
                DatabaseSource.AddParameter(command, "@prefix", prefix + "%");
                Require(Convert.ToInt64(await command.ExecuteScalarAsync(deadline.Token)) == count,
                    "Local retention removed replicated server history.");
            }
            File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
            {
                connections = count, server_commit_failure_preserved_data = true, concurrent_resume = true,
                multiple_destinations_acknowledged = true, offline_consumer_protected = true,
                automatic_pruning = true, foreign_keys = true, replicated_history_preserved = true
            }, new JsonSerializerOptions { WriteIndented = true }));

        }
        finally
        {
            Microsoft.Data.SqlClient.SqlConnection.ClearAllPools();
            Npgsql.NpgsqlConnection.ClearAllPools();
            foreach (var (admin, name) in adminTargets)
            {
                using var server = await admin.OpenConnectionAsync(CancellationToken.None);
                using var command = server.CreateCommand();
                command.CommandText = admin.Provider == DatabaseProvider.SqlServer ?
                    $"DROP DATABASE [{name}]" : $"DROP DATABASE \"{name}\" WITH (FORCE)";
                await command.ExecuteNonQueryAsync(CancellationToken.None);
            }
        }

    }
}
