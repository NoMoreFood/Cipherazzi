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
                    while ((await Replication.SyncAsync(path, target, deadline.Token)).More) { }
                }
                await Task.WhenAll(CatchUp(), CatchUp());
            }
            Require(Local("SELECT count(*) FROM replication_consumers WHERE acknowledged_revision=" + available) == 2,
                "All destinations did not acknowledge the committed source revision.");
            var emptyCapture = Path.Combine(directory, "empty.pcap");
            File.WriteAllBytes(emptyCapture, [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0]);
            async Task Maintain(string? journal = null)
            {
                long Remaining()
                {
                    using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                        { DataSource = journal ?? path, Pooling = false }.ToString());
                    connection.Open();
                    using var command = connection.CreateCommand();
                    command.CommandText = "SELECT (SELECT count(*) FROM connections) + " +
                        "(SELECT count(*) FROM endpoint_events) + (SELECT count(*) FROM certificates)";
                    return Convert.ToInt64(command.ExecuteScalar());
                }
                var before = Remaining();
                for (;;)
                {
                    var info = new ProcessStartInfo(Path.GetFullPath(args[2]))
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    foreach (var value in new[] { "--db", journal ?? path, "--replay", emptyCapture,
                        "--retention-days", "1", "--retention-mb", "0", "--replication-required" })
                        info.ArgumentList.Add(value);
                    using var process = Process.Start(info)!;
                    var output = process.StandardOutput.ReadToEndAsync();
                    var error = process.StandardError.ReadToEndAsync();
                    await process.WaitForExitAsync(deadline.Token);
                    Require(process.ExitCode == 0, "Collector retention failed: " + await error);
                    await output;

                    // Cleanup yields between bounded batches; repeat until protection or an empty scope stops it.
                    var after = Remaining();
                    if (after == before)
                        return;
                    Require(after < before, "An empty replay unexpectedly added retained metadata.");
                    before = after;
                }
            }

            // A restored destination must protect its missing history even when its first retry fails.
            foreach (var target in targets)
            {
                using var destination = await target.OpenConnectionAsync(deadline.Token);
                using var command = destination.CreateCommand();
                command.CommandText = """
                    DELETE FROM cipherazzi.connection_certificates;
                    DELETE FROM cipherazzi.connections;
                    DELETE FROM cipherazzi.endpoint_events;
                    DELETE FROM cipherazzi.certificates;
                    DELETE FROM cipherazzi.capture_sessions;
                    UPDATE cipherazzi.replication_sources SET revision=0;
                    """;
                await command.ExecuteNonQueryAsync(deadline.Token);
                var constraint = "rollback_" + Guid.NewGuid().ToString("N");
                command.CommandText = $"ALTER TABLE cipherazzi.connections ADD CONSTRAINT {constraint} " +
                    $"CHECK(run_id NOT LIKE '{prefix}%')";
                await command.ExecuteNonQueryAsync(deadline.Token);
                try
                {
                    var failed = false;
                    try { await Replication.SyncAsync(path, target, deadline.Token); }
                    catch (DbException) { failed = true; }
                    Require(failed && Local("SELECT min(acknowledged_revision) FROM replication_consumers") == 0,
                        "A restored destination retained an acknowledgement for missing history.");
                    await Maintain();
                    Require(Local("SELECT count(*) FROM connections") == count,
                        "Retention deleted history needed by a restored destination.");
                }
                finally
                {
                    command.CommandText = $"ALTER TABLE cipherazzi.connections DROP CONSTRAINT {constraint}";
                    await command.ExecuteNonQueryAsync(CancellationToken.None);
                }
                async Task CatchUp()
                {
                    while ((await Replication.SyncAsync(path, target, deadline.Token)).More) { }
                }
                await Task.WhenAll(CatchUp(), CatchUp());
                command.CommandText = "SELECT count(*) FROM cipherazzi.connections";
                Require(Convert.ToInt64(await command.ExecuteScalarAsync(deadline.Token)) == count,
                    "A restored destination did not recover the retained connections.");

                // A new relay protects retained history before it can contact a replacement destination.
                await Replication.RegisterAsync(path, target, deadline.Token);
                Require(Local("SELECT min(acknowledged_revision) FROM replication_consumers") == 0,
                    "Relay registration left an old destination acknowledgement active.");
                await CatchUp();
            }
            Modify("INSERT INTO replication_consumers VALUES('offline',0,0)");
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
            foreach (var target in targets)
                foreach (var sameIdentity in new[] { false, true })
                    await VerifySourceReplacementAsync(args[0], directory, target, Maintain,
                        sameIdentity, deadline.Token);
            File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
            {
                connections = count,
                server_commit_failure_preserved_data = true,
                concurrent_resume = true,
                multiple_destinations_acknowledged = true,
                offline_consumer_protected = true,
                destination_rollback_recovered = true,
                registration_protected = true,
                source_replacement_protected = true,
                automatic_pruning = true,
                foreign_keys = true,
                replicated_history_preserved = true
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

    private static async Task VerifySourceReplacementAsync(string seed, string directory, DatabaseSource target,
        Func<string, Task> maintain, bool sameIdentity, CancellationToken cancellation)
    {
        var scenario = $"{target.Provider}-{(sameIdentity ? "rollback" : "replacement")}";
        var path = Path.Combine(directory, $"source-change-{scenario}.db");
        var replacementPath = Path.Combine(directory, $"replacement-{scenario}.db");
        (string Id, string Prefix, long Count) Prepare(string destination, long revision, string? existingId = null)
        {
            using var original = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = seed, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            using var copy = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = destination, Pooling = false }.ToString());
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
            var prefix = Guid.NewGuid().ToString("N") + "-";
            var id = existingId ?? Guid.NewGuid().ToString("N");
            using var command = copy.CreateCommand();
            command.CommandText = """
                PRAGMA foreign_keys=OFF;
                BEGIN IMMEDIATE;
                UPDATE metadata SET database_id=@id,revision=@revision,observation_revision=@revision;
                UPDATE capture_sessions SET id=@prefix||id,started_us=1,updated_us=2,stopped_us=2,
                    status='stopped',change_revision=@revision;
                UPDATE connections SET run_id=@prefix||run_id,first_us=1,last_us=2,ended_us=2,
                    change_revision=@revision;
                UPDATE connection_certificates SET run_id=@prefix||run_id,change_revision=@revision;
                UPDATE certificates SET change_revision=@revision;
                UPDATE endpoint_events SET id=@prefix||id,run_id=@prefix||run_id,timestamp_us=2,
                    change_revision=@revision;
                UPDATE endpoint_certificates SET event_id=@prefix||event_id;
                CREATE TABLE IF NOT EXISTS replication_consumers(target_id TEXT PRIMARY KEY,
                    acknowledged_revision INTEGER NOT NULL CHECK(acknowledged_revision>=0),
                    updated_us INTEGER NOT NULL) STRICT;
                DELETE FROM replication_consumers;
                COMMIT;
                SELECT count(*) FROM connections;
                """;
            command.Parameters.AddWithValue("@id", id);
            command.Parameters.AddWithValue("@revision", revision);
            command.Parameters.AddWithValue("@prefix", prefix);
            return (id, prefix, Convert.ToInt64(command.ExecuteScalar()));
        }
        var previous = Prepare(path, 100);
        var replacement = Prepare(replacementPath, 1, sameIdentity ? previous.Id : null);
        using var blocker = await target.OpenConnectionAsync(cancellation);
        using var blocking = await blocker.BeginTransactionAsync(cancellation);
        using var command = blocker.CreateCommand();
        command.Transaction = blocking;
        command.CommandText = target.Provider == DatabaseProvider.SqlServer ? "SELECT @@SPID" :
            "SELECT pg_backend_pid()";
        var session = Convert.ToInt32(await command.ExecuteScalarAsync(cancellation));
        command.CommandText = "UPDATE cipherazzi.metadata SET revision=revision WHERE id=1";
        await command.ExecuteNonQueryAsync(cancellation);
        var syncing = Replication.SyncAsync(path, target, cancellation);
        var changed = false;
        try
        {
            // The blocked destination proves the source snapshot has been read and released before restoration.
            using var observer = await target.OpenConnectionAsync(cancellation);
            using var waiting = observer.CreateCommand();
            waiting.CommandText = target.Provider == DatabaseProvider.SqlServer ?
                "SELECT count(*) FROM sys.dm_exec_requests WHERE database_id=DB_ID() AND blocking_session_id=@pid" :
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' " +
                    "AND pid<>@pid AND query LIKE 'UPDATE cipherazzi.metadata SET revision=revision+1%'";
            DatabaseSource.AddParameter(waiting, "@pid", session);
            var watch = Stopwatch.StartNew();
            while (Convert.ToInt32(await waiting.ExecuteScalarAsync(cancellation)) == 0)
            {
                if (syncing.IsCompleted || watch.Elapsed > TimeSpan.FromSeconds(10))
                    throw new InvalidOperationException("The upload did not reach its destination write lock.");
                await Task.Delay(20, cancellation);
            }
            using var incoming = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = replacementPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            using var current = new SqliteConnection(new SqliteConnectionStringBuilder
                { DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
            incoming.Open();
            current.Open();
            incoming.BackupDatabase(current);
        }
        finally
        {
            await blocking.RollbackAsync(CancellationToken.None);
            try { await syncing; }
            catch (InvalidDataException) { changed = true; }
        }

        // The old upload must not release any of the replacement journal's untransferred history.
        using var local = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Pooling = false }.ToString());
        local.Open();
        using var read = local.CreateCommand();
        read.CommandText = "SELECT min(acknowledged_revision) FROM replication_consumers";
        var acknowledged = Convert.ToInt64(read.ExecuteScalar());
        await maintain(path);
        read.CommandText = "SELECT count(*) FROM connections";
        var remaining = Convert.ToInt64(read.ExecuteScalar());
        var reportPath = Path.Combine(directory, $"source-change-{scenario}.json");
        var report = new
        {
            provider = target.Provider.ToString(),
            original_database_id = previous.Id,
            replacement_database_id = replacement.Id,
            declined_old_acknowledgement = changed,
            acknowledged_revision = acknowledged,
            original_revision = 100,
            replacement_revision = 1,
            replacement_connections = replacement.Count,
            retained_connections = remaining,
            replacement_upload_resumed = false,
            rollback_rejected = false,
            idle_poll_unwritten = false
        };
        File.WriteAllText(reportPath, JsonSerializer.Serialize(report,
            new JsonSerializerOptions { WriteIndented = true }));
        if (!changed || acknowledged != 0 || remaining != replacement.Count)
            throw new InvalidOperationException("An old upload released the replacement journal's retained history.");
        if (sameIdentity)
        {
            // A restored revision of the same identity must stay protected until the operator selects a new journal.
            read.CommandText = "PRAGMA data_version";
            var before = Convert.ToInt64(read.ExecuteScalar());
            for (var poll = 0; poll < 3; poll++)
            {
                var declined = false;
                try { await Replication.SyncAsync(path, target, cancellation); }
                catch (InvalidDataException) { declined = true; }
                if (!declined || Convert.ToInt64(read.ExecuteScalar()) != before)
                    throw new InvalidOperationException("A rolled-back source was accepted or changed during retry.");
            }
            report = report with { rollback_rejected = true, idle_poll_unwritten = true };
            File.WriteAllText(reportPath, JsonSerializer.Serialize(report,
                new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"{target.Provider}: source rollback preserves {remaining} pending connections.");
            return;
        }
        while ((await Replication.SyncAsync(path, target, cancellation)).More) { }
        using var remote = await target.OpenConnectionAsync(cancellation);
        using var count = remote.CreateCommand();
        count.CommandText = "SELECT count(*) FROM cipherazzi.connections WHERE run_id LIKE @prefix";
        DatabaseSource.AddParameter(count, "@prefix", replacement.Prefix + "%");
        if (Convert.ToInt64(await count.ExecuteScalarAsync(cancellation)) != replacement.Count)
            throw new InvalidOperationException("The replacement journal did not resume its own upload.");

        // Identity checks must not turn caught-up relay polls into source-journal writes.
        read.CommandText = "PRAGMA data_version";
        var version = Convert.ToInt64(read.ExecuteScalar());
        for (var poll = 0; poll < 3; poll++)
        {
            var idle = await Replication.SyncAsync(path, target, cancellation);
            if (idle.Connections != 0 || idle.More || Convert.ToInt64(read.ExecuteScalar()) != version)
                throw new InvalidOperationException("An idle relay poll modified the protected source journal.");
        }
        report = report with { replacement_upload_resumed = true, idle_poll_unwritten = true };
        File.WriteAllText(reportPath, JsonSerializer.Serialize(report,
            new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"{target.Provider}: source replacement preserves {remaining} pending connections.");
    }
}
