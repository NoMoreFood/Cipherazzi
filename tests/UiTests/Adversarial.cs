using System.Diagnostics;
using System.Data.Common;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

namespace Cipherazzi.UiTests;

internal static class Adversarial
{
    private sealed class StalledServer : IDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stopping = new();
        private readonly List<TcpClient> clients = [];
        public TaskCompletionSource Accepted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

        public StalledServer()
        {
            listener.Start();
            _ = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!stopping.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync(stopping.Token);
                    lock (clients)
                        clients.Add(client);
                    Accepted.TrySetResult();
                }
            }
            catch (Exception) when (stopping.IsCancellationRequested) {}
        }

        public void Dispose()
        {
            stopping.Cancel();
            listener.Stop();
            lock (clients)
                foreach (var client in clients)
                    client.Dispose();
        }
    }

    [STAThread]
    public static int Run(string[] args)
    {
        var directory = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(directory);
        var results = new List<object>();
        var errors = new List<string>();
        Application.ThreadException += (_, e) => errors.Add(e.Exception.ToString());
        using var runner = new Form
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
        };
        var failed = false;
        runner.Shown += async (_, _) =>
        {
            try
            {
                async Task Scenario(string name, DatabaseProvider provider, Func<Task<object>> action)
                {
                    var watch = Stopwatch.StartNew();
                    try
                    {
                        results.Add(new { scenario = name, provider = provider.ToString(), result = "passed",
                            metrics = await action(), elapsed_ms = watch.Elapsed.TotalMilliseconds });
                    }
                    catch (Exception error)
                    {
                        failed = true;
                        results.Add(new { scenario = name, provider = provider.ToString(), result = "failed",
                            elapsed_ms = watch.Elapsed.TotalMilliseconds, error = error.ToString() });
                    }
                }
                foreach (var provider in new[] { DatabaseProvider.SqlServer, DatabaseProvider.PostgreSql })
                    await Scenario("close_stalled_connection", provider, async () => new
                    {
                        close_ms = await CloseStalledConnectionAsync(runner, provider)
                    });
                var path = Path.Combine(directory, "ui.db");
                using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
                using (var copy = new SqliteConnection($"Data Source={path}"))
                {
                    source.Open();
                    copy.Open();
                    source.BackupDatabase(copy);
                    using var command = copy.CreateCommand();
                    command.CommandText = "PRAGMA journal_mode=DELETE";
                    command.ExecuteNonQuery();
                }
                var sources = new List<DatabaseSource> { DatabaseSource.Sqlite(path) };
                await Scenario("source_replacement_and_corruption_recovery", DatabaseProvider.Sqlite,
                    () => SourceRecoveryAsync(runner, sources[0], directory));
                await Scenario("policy_validation_recovery", DatabaseProvider.Sqlite,
                    () => FailureRecovery.PoliciesAsync(runner, directory));
                await Scenario("baseline_failure_recovery", DatabaseProvider.Sqlite,
                    () => FailureRecovery.BaselinesAsync(runner, sources[0], directory));
                await Scenario("corrupt_analytics_shutdown", DatabaseProvider.Sqlite,
                    () => FailureRecovery.AnalyticsAsync(runner, sources[0], directory));
                if (args.Length > 2)
                    foreach (var provider in new[] { DatabaseProvider.SqlServer, DatabaseProvider.PostgreSql })
                        sources.Add(new(provider, File.ReadAllText(Path.Combine(args[2], provider + ".connection"))));
                foreach (var source in sources)
                {
                    await Scenario("close_locked_metadata", source.Provider,
                        () => CloseLockedQueryAsync(runner, source, "metadata", 0));
                    if (source.Provider != DatabaseProvider.Sqlite)
                        for (var index = 0; index < 7; ++index)
                        {
                            var tab = index;
                            await Scenario("close_locked_view_" + tab, source.Provider,
                                () => CloseLockedQueryAsync(runner, source,
                                    tab == 3 ? "endpoint_events" : tab == 5 ? "certificates" : "connections", tab));
                        }
                    await Scenario("rapid_navigation", source.Provider, () => RapidNavigationAsync(runner, source));
                }
                failed |= errors.Count != 0;
            }
            catch (Exception error)
            {
                failed = true;
                errors.Add(error.ToString());
            }
            finally
            {
                File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
                {
                    result = failed ? "failed" : "passed", scenarios = results, unhandled_ui_errors = errors
                }, new JsonSerializerOptions { WriteIndented = true }));
                runner.Close();
            }
        };
        Application.Run(runner);
        return failed ? 1 : 0;
    }

    private static async Task<double> CloseStalledConnectionAsync(Form runner, DatabaseProvider provider)
    {
        // A reachable server that never answers exercises cancellation beyond the socket connect phase.
        using var server = new StalledServer();
        var connection = provider == DatabaseProvider.SqlServer ? new SqlConnectionStringBuilder
        {
            DataSource = $"tcp:127.0.0.1,{server.Port}", InitialCatalog = "stress", UserID = "stress",
            Password = "stress", Encrypt = SqlConnectionEncryptOption.Optional, TrustServerCertificate = true,
            ConnectTimeout = 30, ConnectRetryCount = 0, Pooling = false
        }.ToString() : new NpgsqlConnectionStringBuilder
        {
            Host = "127.0.0.1", Port = server.Port, Database = "stress", Username = "stress", Password = "stress",
            Timeout = 30, SslMode = SslMode.Disable, Pooling = false
        }.ToString();
        using var window = new MainForm(new(provider, connection), null, new ViewerSettings { Live = false })
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
        };
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        window.FormClosed += (_, _) => closed.TrySetResult();
        window.Show(runner);
        await server.Accepted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(100);
        var watch = Stopwatch.StartNew();
        window.Close();
        var responsive = await Task.WhenAny(closed.Task, Task.Delay(3000)) == closed.Task;
        var milliseconds = watch.Elapsed.TotalMilliseconds;

        // Release the test server after the deadline so a failure cannot strand the test message loop.
        server.Dispose();
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(8));
        if (!responsive)
            throw new InvalidOperationException($"Closing waited for an unresponsive {provider} login.");
        return milliseconds;
    }

    private static async Task<object> CloseLockedQueryAsync(Form runner, DatabaseSource source, string table, int tab)
    {
        // Hold a real transaction lock until cancellation completes, so timeouts cannot mask a shutdown hang.
        using DbConnection blocker = source.Provider == DatabaseProvider.Sqlite ?
            new SqliteConnection($"Data Source={source.FilePath};Pooling=False") : source.CreateConnection();
        await blocker.OpenAsync();
        using var transaction = await blocker.BeginTransactionAsync();
        using (var command = blocker.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = source.Provider switch
            {
                DatabaseProvider.Sqlite => "UPDATE metadata SET revision=revision; PRAGMA locking_mode=EXCLUSIVE",
                DatabaseProvider.SqlServer => $"SELECT count(*) FROM {source.Prefix}{table} WITH (TABLOCKX,HOLDLOCK)",
                _ => $"LOCK TABLE {source.Prefix}{table} IN ACCESS EXCLUSIVE MODE"
            };
            await command.ExecuteNonQueryAsync();
        }
        if (source.Provider == DatabaseProvider.Sqlite)
        {
            // An exclusive DELETE-journal transaction also prevents readers from reaching the schema check.
            await transaction.CommitAsync();
            using var command = blocker.CreateCommand();
            command.CommandText = "BEGIN EXCLUSIVE; UPDATE metadata SET revision=revision";
            command.ExecuteNonQuery();
        }
        using var window = Window(source);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        window.FormClosed += (_, _) => closed.TrySetResult();
        window.Show(runner);
        Descendants(window).OfType<TabControl>().Single(tabControl => tabControl.AccessibleName == "Workspace views").SelectedIndex = tab;
        await Task.Delay(150);
        var watch = Stopwatch.StartNew();
        window.Close();
        var responsive = await Task.WhenAny(closed.Task, Task.Delay(3000)) == closed.Task;
        var milliseconds = watch.Elapsed.TotalMilliseconds;
        if (source.Provider == DatabaseProvider.Sqlite)
        {
            using var command = blocker.CreateCommand();
            command.CommandText = "ROLLBACK";
            command.ExecuteNonQuery();
        }
        else
            await transaction.RollbackAsync();
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(8));
        if (!responsive)
            throw new InvalidOperationException($"Closing waited on a locked {table} table.");
        return new { close_ms = milliseconds, tab };
    }

    private static async Task<object> RapidNavigationAsync(Form runner, DatabaseSource source)
    {
        using var window = Window(source);
        window.Show(runner);
        var controls = Descendants(window).ToList();
        var tabs = controls.OfType<TabControl>().Single(tabControl => tabControl.AccessibleName == "Workspace views");
        var grid = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
        var search = controls.OfType<TextBox>().Single(control => control.PlaceholderText.Length != 0);
        var live = controls.OfType<CheckBox>().Single(control => control.Text == "&Live");
        var refresh = controls.OfType<Button>().Single(control => control.Text == "&Refresh");
        var watch = Stopwatch.StartNew();
        var ticks = 0;
        using var heartbeat = new System.Windows.Forms.Timer { Interval = 25 };
        heartbeat.Tick += (_, _) => ++ticks;
        heartbeat.Start();
        try { await Until(() => grid.RowCount > 0 && refresh.Enabled); }
        catch (Exception error)
        {
            var diagnostic = typeof(MainForm).GetField("diagnostics", BindingFlags.NonPublic | BindingFlags.Instance);
            throw new InvalidOperationException("Initial view failed: " + diagnostic?.GetValue(window), error);
        }

        // Deliberately overlap filters, tabs, refreshes, live state, resizing, and property selection.
        for (var index = 0; index < 240; ++index)
        {
            tabs.SelectedIndex = index % 7;
            search.Text = index % 3 == 0 ? "no-match-'_%Δ" : index % 3 == 1 ? "TLS" : "";
            live.Checked = index % 5 != 0;
            if (refresh.Enabled)
                refresh.PerformClick();
            window.ClientSize = index % 2 == 0 ? new Size(1040, 700) : new Size(1600, 950);
            if (grid.RowCount > 0)
                grid.CurrentCell = grid.Rows[index % grid.RowCount].Cells["Sni"];
            await Task.Delay(10);
        }
        tabs.SelectedIndex = 0;
        search.Text = "no-match-'_%Δ";
        await Task.Delay(500);
        await Until(() => refresh.Enabled && grid.RowCount == 0);
        search.Clear();
        await Until(() => refresh.Enabled && grid.RowCount > 0);
        var current = grid.Rows[0].Cells["Sni"].Value?.ToString();
        if (ticks < 30)
            throw new InvalidOperationException("UI events were starved during navigation.");
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        window.FormClosed += (_, _) => closed.TrySetResult();
        tabs.SelectedIndex = 2;
        window.Close();
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        return new { actions = 240, message_loop_ticks = ticks, seconds = watch.Elapsed.TotalSeconds, current };
    }

    private static async Task<object> SourceRecoveryAsync(Form runner, DatabaseSource source, string directory)
    {
        var alternatePath = Path.Combine(directory, "alternate.db");
        File.Copy(source.FilePath, alternatePath, true);
        using (var writer = new SqliteConnection($"Data Source={alternatePath};Pooling=False"))
        {
            writer.Open();
            using var command = writer.CreateCommand();
            command.CommandText = "UPDATE connections SET sni='alternate-'||sni";
            command.ExecuteNonQuery();
        }
        using var window = Window(source);
        window.Show(runner);
        var grid = Descendants(window).OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
        var refresh = Descendants(window).OfType<Button>().Single(control => control.Text == "&Refresh");
        await Until(() => grid.RowCount > 0 && refresh.Enabled);
        var flags = BindingFlags.NonPublic | BindingFlags.Instance;
        var setSource = typeof(MainForm).GetMethod("SetSource", flags)!;
        var load = typeof(MainForm).GetMethod("RefreshAsync", flags)!;
        Task Change(DatabaseSource selected)
        {
            setSource.Invoke(window, [selected]);
            return (Task)load.Invoke(window, [true, false])!;
        }

        // Replace the source while earlier reads and property loads are still completing.
        var pending = new List<Task>();
        for (var index = 0; index < 40; ++index)
        {
            pending.Add(Change(index % 2 == 0 ? source : DatabaseSource.Sqlite(alternatePath)));
            await Task.Delay(5);
        }
        await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(10));
        await Until(() => grid.RowCount > 0 && refresh.Enabled);
        if (!grid.Rows[0].Cells["Sni"].Value!.ToString()!.StartsWith("alternate-"))
            throw new InvalidOperationException("A replaced source published stale rows from an earlier query.");

        // A damaged journal must clear the old scope, report failure, and recover after replacement.
        var broken = Path.Combine(directory, "damaged.db");
        File.WriteAllBytes(broken, new byte[512]);
        await Change(DatabaseSource.Sqlite(broken));
        if (grid.RowCount != 0 || !refresh.Enabled)
            throw new InvalidOperationException("A damaged database retained stale rows or disabled recovery.");
        File.Copy(source.FilePath, broken, true);
        refresh.PerformClick();
        await Until(() => grid.RowCount > 0 && refresh.Enabled);
        var closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        window.FormClosed += (_, _) => closed.TrySetResult();
        window.Close();
        await closed.Task.WaitAsync(TimeSpan.FromSeconds(3));
        return new { source_changes = 40, stale_results_rejected = true, damaged_journal_recovered = true };
    }

    private static MainForm Window(DatabaseSource source) => new(source, null,
        new ViewerSettings { Live = false, AnalyticsMinutes = 0 })
    {
        ShowInTaskbar = false, StartPosition = FormStartPosition.Manual, Location = new Point(-20000, -20000)
    };

    private static IEnumerable<Control> Descendants(Control control)
    {
        foreach (Control child in control.Controls)
        {
            yield return child;
            foreach (var descendant in Descendants(child))
                yield return descendant;
        }
    }

    private static async Task Until(Func<bool> condition)
    {
        var watch = Stopwatch.StartNew();
        while (!condition())
        {
            if (watch.Elapsed > TimeSpan.FromSeconds(10))
                throw new TimeoutException("UI did not settle after stress actions.");
            await Task.Delay(10);
        }
    }
}
