using System.Data.Common;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

internal static class PackagedConnectivity
{
    private static string credentialDirectory = "";

    public static async Task RunAsync(string[] args)
    {
        if (args.Length != 4)
            throw new ArgumentException(
                "Supply the capture database, replay PCAP, output directory, and package directory.");
        var directory = Path.GetFullPath(args[2]);
        credentialDirectory = directory;
        var package = Path.GetFullPath(args[3]);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "capture.db");
        if (File.Exists(path))
            throw new ArgumentException("Choose a new output directory.");

        // Isolate the journal identity and run IDs while preserving real captured metadata and certificates.
        using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
        {
            source.Open();
            copy.Open();
            source.BackupDatabase(copy);
            using var command = copy.CreateCommand();
            command.CommandText = """
                PRAGMA foreign_keys=OFF;
                BEGIN IMMEDIATE;
                UPDATE metadata SET database_id=lower(hex(randomblob(16)));
                UPDATE capture_sessions SET id=@prefix||id;
                UPDATE connections SET run_id=@prefix||run_id;
                UPDATE connection_certificates SET run_id=@prefix||run_id;
                UPDATE endpoint_events SET id=@prefix||id,run_id=@prefix||run_id;
                COMMIT;
                """;
            command.Parameters.AddWithValue("@prefix", Guid.NewGuid().ToString("N"));
            command.ExecuteNonQuery();
        }
        var local = DatabaseSource.Sqlite(path);
        var collector = Path.Combine(package, "Cipherazzi.Collector.exe");
        var relay = Path.Combine(package, "Cipherazzi.Relay.exe");
        var viewer = Path.Combine(package, "Cipherazzi.Viewer.exe");
        var targets = new[]
        {
            DatabaseSource.FromEnvironment("sqlserver", "CIPHERAZZI_SQLSERVER"),
            DatabaseSource.FromEnvironment("postgresql", "CIPHERAZZI_POSTGRESQL")
        };
        var results = new List<object>();
        await RunAsync(viewer, ["--verify-ui", path, Path.Combine(directory, "Sqlite.png")], null,
            Path.Combine(directory, "Sqlite-viewer.log"));
        foreach (var target in targets)
        {
            var provider = target.Provider == DatabaseProvider.SqlServer ? "sqlserver" : "postgresql";
            var name = target.Provider.ToString();
            string[] relayArguments = ["--source", path, "--provider", provider];
            await RunAsync(relay, [.. relayArguments, "--once"], target,
                Path.Combine(directory, name + "-initial.log"));
            VerifyCopy(local, target);
            await RunAsync(viewer, ["--verify-ui", "--provider", provider, Path.Combine(directory, name + ".png")],
                target, Path.Combine(directory, name + "-viewer.log"));

            // Take only the disposable database offline; other databases and server processes stay available.
            await using var admin = CreateAdmin(target, out var database);
            await admin.OpenAsync();
            using var process = Start(relay, relayArguments, target);
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            var offline = false;
            var before = Convert.ToInt64(Scalar(local, "SELECT count(*) FROM connections"));
            double recoveryMilliseconds;
            try
            {
                using (var writer = new SqliteConnection(
                    new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
                {
                    writer.Open();
                    using var update = writer.CreateCommand();
                    update.CommandText = """
                        BEGIN IMMEDIATE;
                        UPDATE metadata SET revision=revision+1;
                        UPDATE connections SET detail='Connectivity lab late update',
                            change_revision=(SELECT revision FROM metadata)
                            WHERE id=(SELECT min(id) FROM connections);
                        COMMIT;
                        """;
                    update.ExecuteNonQuery();
                }
                await WaitAsync(() => CursorMatches(local, target), process);
                VerifyCopy(local, target);
                offline = true;
                await SetAvailableAsync(admin, target.Provider, database, false);
                var unavailable = false;
                try { Scalar(target, "SELECT 1"); }
                catch (DbException) { unavailable = true; }
                Require(unavailable, "The destination remained available during the outage.");

                // Exercise the native collector while the relay cannot contact its destination.
                await RunAsync(collector, ["--db", path, "--replay", Path.GetFullPath(args[1])], null,
                    Path.Combine(directory, name + "-collector.log"));
                Require(Convert.ToInt64(Scalar(local, "SELECT count(*) FROM connections")) > before,
                    "Collection did not advance during the outage.");
                Require(Scalar(local, "PRAGMA integrity_check")?.ToString() == "ok",
                    "The local journal failed its integrity check.");
                Require(Scalar(local, "PRAGMA foreign_key_check") is null, "The local journal contains orphan rows.");
                await Task.Delay(4000);
                Require(!process.HasExited, "The continuous relay exited during the outage.");
                await SetAvailableAsync(admin, target.Provider, database, true);
                offline = false;
                var watch = Stopwatch.StartNew();
                await WaitAsync(() => CursorMatches(local, target), process);
                recoveryMilliseconds = watch.Elapsed.TotalMilliseconds;
                VerifyCopy(local, target);
            }
            finally
            {
                try
                {
                    if (offline)
                        await SetAvailableAsync(admin, target.Provider, database, true);
                }
                finally
                {
                    if (!process.HasExited)
                        process.Kill();
                    await process.WaitForExitAsync();
                    await File.WriteAllTextAsync(Path.Combine(directory, name + "-relay.log"),
                        await output + Environment.NewLine + await error);
                }
            }
            Require((await error).Contains("Replication interrupted; the local journal is retained."),
                "The relay did not observe the forced outage.");
            await RunAsync(relay, [.. relayArguments, "--once"], target,
                Path.Combine(directory, name + "-restart.log"));
            VerifyCopy(local, target);
            results.Add(new
            {
                provider = name, outage_recovery_ms = recoveryMilliseconds,
                source_rows = Convert.ToInt64(Scalar(local, "SELECT count(*) FROM connections")),
                automatic_reconnect = true, native_collection_during_outage = true, restart_idempotent = true,
                complete_data_roundtrip = true, packaged_viewer = true, live_updates = true
            });
            Console.WriteLine(name + ": packaged relay, viewer, offline collection, recovery, and restart passed.");
        }

        // Bring both destinations to the final journal state and compare every captured table again.
        foreach (var target in targets)
        {
            var provider = target.Provider == DatabaseProvider.SqlServer ? "sqlserver" : "postgresql";
            await RunAsync(relay, ["--source", path, "--provider", provider, "--once"], target,
                Path.Combine(directory, target.Provider + "-final.log"));
            VerifyCopy(local, target);
        }
        await File.WriteAllTextAsync(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
        {
            results, packaged_sqlite_viewer = true, journal = path,
            final_rows = Convert.ToInt64(Scalar(local, "SELECT count(*) FROM connections")),
            certificates = Convert.ToInt64(Scalar(local, "SELECT count(*) FROM certificates")),
            certificate_links = Convert.ToInt64(Scalar(local, "SELECT count(*) FROM connection_certificates")),
            endpoint_events = Convert.ToInt64(Scalar(local, "SELECT count(*) FROM endpoint_events"))
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static DbConnection CreateAdmin(DatabaseSource target, out string database)
    {
        DbConnectionStringBuilder builder;
        if (target.Provider == DatabaseProvider.SqlServer)
        {
            var sql = new SqlConnectionStringBuilder(target.ConnectionString);
            database = sql.InitialCatalog;
            sql.InitialCatalog = "master";
            sql.Pooling = false;
            builder = sql;
        }
        else
        {
            var postgres = new NpgsqlConnectionStringBuilder(target.ConnectionString);
            database = postgres.Database ?? "";
            postgres.Database = "postgres";
            postgres.Pooling = false;
            builder = postgres;
        }
        Require(Regex.IsMatch(database, "^CipherazziCrypto_[0-9a-f]{10}$"),
            "Outage testing requires a disposable database created with DatabaseLab --fresh.");
        return new DatabaseSource(target.Provider, builder.ConnectionString).CreateConnection();
    }

    private static async Task SetAvailableAsync(DbConnection admin, DatabaseProvider provider, string database,
        bool available)
    {
        using var command = admin.CreateCommand();
        command.CommandTimeout = 30;
        command.CommandText = provider == DatabaseProvider.SqlServer ?
            $"ALTER DATABASE [{database}] SET " + (available ? "ONLINE" : "OFFLINE WITH ROLLBACK IMMEDIATE") :
            $"ALTER DATABASE \"{database}\" ALLOW_CONNECTIONS " + (available ? "true" : "false");
        await command.ExecuteNonQueryAsync();
        if (provider == DatabaseProvider.PostgreSql && !available)
        {
            command.CommandText = "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=@database";
            DatabaseSource.AddParameter(command, "@database", database);
            await command.ExecuteNonQueryAsync();
        }
    }

    private static object? Scalar(DatabaseSource source, string sql)
    {
        using var connection = source.CreateConnection();
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.CommandTimeout = 5;
        return command.ExecuteScalar();
    }

    private static bool CursorMatches(DatabaseSource local, DatabaseSource target)
    {
        var sourceId = Scalar(local, "SELECT database_id FROM metadata")!.ToString()!;
        using var connection = target.CreateConnection();
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT revision FROM cipherazzi.replication_sources WHERE source_id=@source";
        DatabaseSource.AddParameter(command, "@source", sourceId);
        return Convert.ToInt64(command.ExecuteScalar()) ==
            Convert.ToInt64(Scalar(local, "SELECT revision FROM metadata"));
    }

    private static void VerifyCopy(DatabaseSource local, DatabaseSource target)
    {
        using var original = local.CreateConnection();
        using var copy = target.CreateConnection();
        original.Open();
        copy.Open();
        using var runs = original.CreateCommand();
        runs.CommandText = "SELECT id FROM capture_sessions ORDER BY id";
        var ids = new List<string>();
        using (var reader = runs.ExecuteReader())
            while (reader.Read())
                ids.Add(reader.GetString(0));
        var parameters = string.Join(',', ids.Select((_, index) => "@run" + index));
        foreach (var table in new[] { "capture_sessions", "connections", "connection_certificates", "endpoint_events",
            "certificates" })
        {
            string Fingerprint(DbConnection connection, string prefix)
            {
                using var command = connection.CreateCommand();
                var filter = table == "certificates" ?
                    $"sha256 IN(SELECT sha256 FROM {prefix}connection_certificates WHERE run_id IN({parameters}))" :
                    (table == "capture_sessions" ? "id" : "run_id") + $" IN({parameters})";
                command.CommandText = $"SELECT * FROM {prefix}{table} WHERE {filter}";
                for (var index = 0; index < ids.Count; ++index)
                    DatabaseSource.AddParameter(command, "@run" + index, ids[index]);
                using var reader = command.ExecuteReader();
                var columns = Enumerable.Range(0, reader.FieldCount)
                    .Where(index => reader.GetName(index) != "change_revision" &&
                        (table != "connections" || reader.GetName(index) != "id"))
                    .OrderBy(index => reader.GetName(index)).ToArray();
                var rows = new List<string>();
                while (reader.Read())
                {
                    var values = columns.Select(index => reader.IsDBNull(index) ? null :
                        reader[index] is byte[] bytes ? Convert.ToHexString(bytes) :
                        Convert.ToString(reader[index], System.Globalization.CultureInfo.InvariantCulture));
                    rows.Add(JsonSerializer.Serialize(values));
                }

                // Canonical ordering makes data equality independent of database collation.
                rows.Sort(StringComparer.Ordinal);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                foreach (var row in rows)
                    hash.AppendData(Encoding.UTF8.GetBytes(row));
                return Convert.ToHexString(hash.GetHashAndReset());
            }
            Require(Fingerprint(original, "") == Fingerprint(copy, target.Prefix),
                "Replicated data differs for " + table + ".");
        }
        Require(CursorMatches(local, target), "The destination cursor did not catch up.");
    }

    private static Process Start(string executable, string[] arguments, DatabaseSource? target)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        if (target is not null)
        {
            var path = Path.Combine(credentialDirectory, target.Provider + ".credential");
            ConnectionCredentials.Save(path, target);
            start.ArgumentList.Add("--connection-file");
            start.ArgumentList.Add(path);
        }
        return Process.Start(start) ?? throw new InvalidOperationException("Could not start " + executable);
    }

    private static async Task RunAsync(string executable, string[] arguments, DatabaseSource? target, string log)
    {
        using var process = Start(executable, arguments, target);
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try { await process.WaitForExitAsync(timeout.Token); }
        finally
        {
            if (!process.HasExited)
                process.Kill();
            await process.WaitForExitAsync();
            await File.WriteAllTextAsync(log, await output + Environment.NewLine + await error);
        }
        Require(process.ExitCode == 0, Path.GetFileName(executable) + " failed; see " + log);
    }

    private static async Task WaitAsync(Func<bool> condition, Process process)
    {
        var watch = Stopwatch.StartNew();
        while (true)
        {
            Require(!process.HasExited, "The relay exited before its cursor caught up.");
            try { if (condition()) return; }
            catch (DbException) {}
            Require(watch.Elapsed < TimeSpan.FromSeconds(45), "The relay did not recover within 45 seconds.");
            await Task.Delay(200);
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}
