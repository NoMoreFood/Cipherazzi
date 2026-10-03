using System.Data.Common;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

internal static class StressConnectivity
{
    public static async Task RunAsync(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var path = Path.Combine(output, "source.db");
        using (var original = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
        using (var copy = new SqliteConnection($"Data Source={path};Pooling=False"))
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
            using var command = copy.CreateCommand();
            command.CommandText = "UPDATE metadata SET database_id=lower(hex(randomblob(16)))";
            command.ExecuteNonQuery();
        }
        var source = DatabaseSource.Sqlite(path);
        var results = new List<object>();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var originals = new[]
        {
            DatabaseSource.FromEnvironment("sqlserver", "CIPHERAZZI_SQLSERVER"),
            DatabaseSource.FromEnvironment("postgresql", "CIPHERAZZI_POSTGRESQL")
        };
        foreach (var original in originals)
        {
            Console.WriteLine($"Stress testing {original.Provider} replication.");
            var target = PqcConnectivity.FreshTarget(original);
            ConnectionCredentials.Save(Path.Combine(output, target.Provider + ".credential"), target);
            await Replication.InitializeAsync(target, deadline.Token);
            async Task CatchUp()
            {
                while ((await Replication.SyncAsync(path, target, deadline.Token)).More) {}
            }
            await CatchUp();
            if (Fingerprint(source) != Fingerprint(target))
                throw new InvalidOperationException("Initial replication changed the source evidence.");
            var cursor = Revision(target);
            Bump(path);

            // Cancel a destination transaction while another session holds the durable-cursor lock.
            using (var blocker = target.CreateConnection())
            {
                await blocker.OpenAsync(deadline.Token);
                using var transaction = await blocker.BeginTransactionAsync(deadline.Token);
                using var command = blocker.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = target.Provider == DatabaseProvider.SqlServer ?
                    "SELECT count(*) FROM cipherazzi.metadata WITH (TABLOCKX,HOLDLOCK)" :
                    "LOCK TABLE cipherazzi.metadata IN ACCESS EXCLUSIVE MODE";
                await command.ExecuteNonQueryAsync(deadline.Token);
                using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
                var watch = Stopwatch.StartNew();
                var canceled = false;
                try
                {
                    await Task.Run(() => Replication.SyncAsync(path, target, cancellation.Token))
                        .WaitAsync(TimeSpan.FromSeconds(4));
                }
                catch (OperationCanceledException) { canceled = true; }
                catch (DbException) when (cancellation.IsCancellationRequested) { canceled = true; }
                if (!canceled || watch.Elapsed > TimeSpan.FromSeconds(4))
                    throw new InvalidOperationException("A locked replication transaction did not cancel promptly.");
                if (args.Length > 2)
                    results.Add(await StopRelayAsync(path, target, output, args[2], deadline.Token));
                await transaction.RollbackAsync(deadline.Token);
                if (Revision(target) != cursor)
                    throw new InvalidOperationException("Cancellation advanced the durable replication cursor.");
                results.Add(new { scenario = "cancel_locked_replication", provider = target.Provider.ToString(),
                    cancellation_ms = watch.Elapsed.TotalMilliseconds, cursor_unchanged = true });
            }

            // Competing relays must converge after cancellation without duplicates or missing late updates.
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(CatchUp)));
            Bump(path);
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(CatchUp)));
            if (Fingerprint(source) != Fingerprint(target))
                throw new InvalidOperationException("Concurrent recovery changed the source evidence.");
            results.Add(new { scenario = "concurrent_recovery", provider = target.Provider.ToString(),
                competing_relays = 8, exact_rows_json_certificates_links_and_health = true });
            results.Add(await StalledLoginAsync(original.Provider));
        }
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        {
            result = "passed", scenarios = results
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Replication cancellation, stalled login, and concurrent recovery passed.");
    }

    private static async Task<object> StalledLoginAsync(DatabaseProvider provider)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var clients = new List<TcpClient>();
        using var stopping = new CancellationTokenSource();
        var accepting = Task.Run(async () =>
        {
            try
            {
                while (!stopping.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync(stopping.Token);
                    lock (clients)
                        clients.Add(client);
                }
            }
            catch (OperationCanceledException) {}
        });
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var connection = provider == DatabaseProvider.SqlServer ? new SqlConnectionStringBuilder
            {
                DataSource = $"tcp:127.0.0.1,{port}", InitialCatalog = "stress", UserID = "stress", Password = "stress",
                Encrypt = SqlConnectionEncryptOption.Optional, TrustServerCertificate = true, Pooling = false,
                ConnectTimeout = 30, ConnectRetryCount = 0
            }.ToString() : new NpgsqlConnectionStringBuilder
            {
                Host = "127.0.0.1", Port = port, Database = "stress", Username = "stress", Password = "stress",
                SslMode = SslMode.Require, Timeout = 30, Pooling = false
            }.ToString();
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            var watch = Stopwatch.StartNew();
            var canceled = false;
            try
            {
                await Replication.InitializeAsync(new(provider, connection), cancellation.Token)
                    .WaitAsync(TimeSpan.FromSeconds(3));
            }
            catch (OperationCanceledException) { canceled = true; }
            if (!canceled)
                throw new InvalidOperationException("A stalled replica connection ignored cancellation.");
            return new { scenario = "cancel_stalled_login", provider = provider.ToString(),
                cancellation_ms = watch.Elapsed.TotalMilliseconds };
        }
        finally
        {
            stopping.Cancel();
            listener.Stop();
            await accepting;
            lock (clients)
                foreach (var client in clients)
                    client.Dispose();
        }
    }

    private static void Bump(string path)
    {
        using var writer = new SqliteConnection($"Data Source={path};Pooling=False");
        writer.Open();
        using var command = writer.CreateCommand();
        command.CommandText = "BEGIN IMMEDIATE; UPDATE metadata SET revision=revision+1;" +
            "UPDATE connections SET change_revision=(SELECT revision FROM metadata); COMMIT;";
        command.ExecuteNonQuery();
    }

    private static async Task<object> StopRelayAsync(string path, DatabaseSource target, string output,
        string relay, CancellationToken cancellation)
    {
        var application = "Cipherazzi relay stop " + Guid.NewGuid().ToString("N")[..8];
        var builder = target.Provider == DatabaseProvider.SqlServer ?
            (DbConnectionStringBuilder)new SqlConnectionStringBuilder(target.ConnectionString) :
            new NpgsqlConnectionStringBuilder(target.ConnectionString);
        builder["Application Name"] = application;
        var signal = Path.Combine(output, target.Provider + ".stop");
        var report = Path.Combine(output, target.Provider + "-stop.json");
        var info = new ProcessStartInfo
        {
            FileName = "C:/Users/Bryan Berns/AppData/Local/Programs/Python/Python312/python.exe",
            UseShellExecute = false, CreateNoWindow = true
        };
        var credentialFile = Path.Combine(output, target.Provider + "-stop.credential");
        ConnectionCredentials.Save(credentialFile, new DatabaseSource(target.Provider, builder.ConnectionString));
        foreach (var argument in new[] { "tests/StopRelay.py", "--relay", relay, "--source", path,
            "--provider", target.Provider == DatabaseProvider.SqlServer ? "sqlserver" : "postgresql",
            "--connection-file", credentialFile, "--signal", signal, "--output", report })
            info.ArgumentList.Add(argument);
        using var helper = Process.Start(info)!;
        try
        {
            using var probe = target.CreateConnection();
            await probe.OpenAsync(cancellation);
            using var command = probe.CreateCommand();
            command.CommandText = target.Provider == DatabaseProvider.SqlServer ?
                "SELECT count(*) FROM sys.dm_exec_sessions s JOIN sys.dm_exec_requests r ON s.session_id=r.session_id " +
                "WHERE s.program_name=@application AND r.blocking_session_id<>0" :
                "SELECT count(*) FROM pg_stat_activity " +
                "WHERE application_name=@application AND wait_event_type='Lock'";
            DatabaseSource.AddParameter(command, "@application", application);
            var watch = Stopwatch.StartNew();
            while (Convert.ToInt64(await command.ExecuteScalarAsync(cancellation)) == 0)
            {
                if (helper.HasExited || watch.Elapsed > TimeSpan.FromSeconds(12))
                    throw new InvalidOperationException("The relay did not enter its locked database operation.");
                await Task.Delay(50, cancellation);
            }
            File.WriteAllText(signal, "stop");
            await helper.WaitForExitAsync(cancellation).WaitAsync(TimeSpan.FromSeconds(8));
            if (helper.ExitCode != 0)
                throw new InvalidOperationException("Stopping the relay during a table lock failed: " +
                    File.ReadAllText(report));
            return new { scenario = "stop_relay_locked_transaction", provider = target.Provider.ToString(),
                metrics = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(report)) };
        }
        finally
        {
            if (!helper.HasExited)
                helper.Kill(true);
        }
    }

    private static long Revision(DatabaseSource source)
    {
        using var connection = source.CreateConnection();
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT revision FROM {source.Prefix}metadata WHERE id=1";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static string Fingerprint(DatabaseSource source)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var connection = source.CreateConnection();
        connection.Open();
        foreach (var (table, key) in new[]
        {
            ("capture_sessions", "id"), ("connections", "run_id,flow_id"), ("endpoint_events", "id"),
            ("certificates", "sha256"), ("connection_certificates", "run_id,flow_id,role,chain_index")
        })
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM {source.Prefix}{table} ORDER BY {key}";
            using var reader = command.ExecuteReader();
            var columns = Enumerable.Range(0, reader.FieldCount).Where(index =>
                reader.GetName(index) != "change_revision" && (table != "connections" || reader.GetName(index) != "id"))
                .OrderBy(reader.GetName).ToArray();
            while (reader.Read())
            {
                var row = columns.Select(index => reader.IsDBNull(index) ? null : reader[index] is byte[] bytes ?
                    Convert.ToHexString(bytes) :
                    Convert.ToString(reader[index], System.Globalization.CultureInfo.InvariantCulture));
                hash.AppendData(Encoding.UTF8.GetBytes(table + ":" + JsonSerializer.Serialize(row)));
            }
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }
}
