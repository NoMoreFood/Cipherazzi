using System.Diagnostics;

namespace Cipherazzi.Publisher;

internal static class Program
{
    private static int Main(string[] args)
        => Cipherazzi.Deployment.Deployment.Run("CipherazziPublisher", args, Run);

    private static int Run(string[] args, CancellationToken cancellation)
    {
        var destinations = new List<IEventDestination>();
        var locks = new List<Mutex>();
        var workers = new List<Task>();
        using var shutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; shutdown.Cancel(); };
        try
        {
            // Validate configuration before registering persistent destination state.
            var options = Options.Parse(args);
            if (options.Help)
            {
                Options.PrintHelp();
                return 0;
            }
            if (options.RegisterSource)
            {
                WindowsDestination.Register(options.WindowsSource, options.MessageFile);
                Console.WriteLine("Registered Application event source: " + options.WindowsSource);
                return 0;
            }
            var policies = options.Events.HasFlag(EventKinds.Policies) ?
                Cipherazzi.Data.PolicyEvaluator.Load(options.PolicyFile!) : null;
            SQLitePCL.Batteries_V2.Init();
            if (cancellation.CanBeCanceled && !File.Exists(options.Source))
            {
                // A collector can create its journal after Windows starts the publishing service.
                Console.WriteLine("Waiting for the source journal: " + options.Source);
                while (!File.Exists(options.Source))
                    Task.Delay(1000, shutdown.Token).GetAwaiter().GetResult();
            }
            if (options.DurationSeconds > 0)
                shutdown.CancelAfter(TimeSpan.FromSeconds(options.DurationSeconds));
            if (options.Syslog is not null)
                destinations.Add(new SyslogDestination(options));
            if (options.WindowsEvents)
                destinations.Add(new WindowsDestination(options.WindowsSource));
            var journals = new List<(Journal Journal, IEventDestination Destination)>();
            foreach (var destination in destinations)
            {
                var journal = new Journal(options.Source, destination.Identity, policies, options.PolicyResults);
                journal.Identify();
                var mutex = new Mutex(false, journal.LockName);
                var acquired = false;
                try
                {
                    try { acquired = mutex.WaitOne(0); }
                    catch (AbandonedMutexException) { acquired = true; }
                    if (!acquired)
                        throw new InvalidOperationException(
                            "A publisher is already using this journal and destination.");
                    locks.Add(mutex);
                    if (options.Unregister)
                    {
                        journal.Unregister();
                        Console.WriteLine("Unregistered destination: " + destination.Identity);
                        continue;
                    }
                    journal.Register(options.StartNow);
                    journals.Add((journal, destination));
                }
                finally
                {
                    if (!acquired)
                        mutex.Dispose();
                }
            }
            // Independent workers keep an unavailable destination from blocking the other output.
            if (journals.Count > 0)
                Console.WriteLine("Publishing started: " + string.Join(", ",
                    journals.Select(item => item.Destination.Identity)));
            foreach (var item in journals)
                workers.Add(Task.Run(() => PublishAsync(item.Journal, item.Destination, options, shutdown.Token)));
            Task.WhenAll(workers).WaitAsync(shutdown.Token).GetAwaiter().GetResult();
            return 0;
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { return 0; }
        catch (Exception error)
        {
            Console.Error.WriteLine("Publisher: " + error.Message);
            return 1;
        }
        finally
        {
            shutdown.Cancel();
            try { Task.WhenAll(workers).Wait(TimeSpan.FromSeconds(6)); }
            catch (AggregateException) {}
            foreach (var destination in destinations)
                destination.Dispose();
            foreach (var mutex in locks)
            {
                mutex.ReleaseMutex();
                mutex.Dispose();
            }
        }
    }

    private static async Task PublishAsync(Journal journal, IEventDestination destination, Options options,
        CancellationToken cancellation)
    {
        var interrupted = false;
        var health = new Dictionary<string, (string Status, long Losses, long Tick)>(StringComparer.Ordinal);
        var window = Stopwatch.StartNew();
        var sentInWindow = 0;
        var total = 0L;
        while (!cancellation.IsCancellationRequested)
        {
            try
            {
                var batch = journal.Read(options.Events, cancellation);
                var emittedHealth = new List<(string Run, string Status, long Losses, long Tick)>();
                foreach (var value in batch.Events)
                {
                    if (value.Position.Kind == 3 && health.TryGetValue(value.Position.Key, out var previous) &&
                        previous.Status == value.HealthStatus &&
                        (previous.Losses == 0) == (value.Losses == 0) &&
                        Environment.TickCount64 - previous.Tick < options.HealthSeconds * 1000L)
                        continue;
                    var messages = value.EmitSnapshot ? new List<PublishedEvent> { value } : [];
                    messages.AddRange(value.Alerts);
                    foreach (var message in messages)
                    {
                        if (window.ElapsedMilliseconds >= 1000)
                        {
                            window.Restart();
                            sentInWindow = 0;
                        }
                        if (sentInWindow >= options.Rate)
                        {
                            var delay = 1000 - (int)window.ElapsedMilliseconds;
                            if (delay > 0)
                                await Task.Delay(delay, cancellation);
                            window.Restart();
                            sentInWindow = 0;
                        }
                        await destination.WriteAsync(message, cancellation);
                        sentInWindow++;
                        total++;
                    }
                    if (value.Position.Kind == 3)
                        emittedHealth.Add((value.Position.Key, value.HealthStatus, value.Losses,
                            Environment.TickCount64));
                }
                cancellation.ThrowIfCancellationRequested();
                if (batch.Next != journal.Cursor)
                    journal.Advance(batch);
                foreach (var value in emittedHealth)
                {
                    if (health.Count >= 1024 && !health.ContainsKey(value.Run))
                        health.Remove(health.MinBy(pair => pair.Value.Tick).Key);
                    health[value.Run] = (value.Status, value.Losses, value.Tick);
                }
                if (interrupted)
                    Console.WriteLine("Publishing resumed: " + destination.Identity);
                interrupted = false;
                if (options.Once && !batch.More)
                {
                    Console.WriteLine($"{destination.Identity}: {total} events; revision {journal.Cursor.Revision}");
                    return;
                }
                if (!batch.More)
                    await Task.Delay(options.PollMilliseconds, cancellation);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { return; }
            catch (Exception error)
            {
                destination.Reset();
                if (options.Once)
                    throw;
                if (!interrupted)
                    Console.Error.WriteLine($"Publishing paused ({destination.Identity}): {error.Message}");
                interrupted = true;
                await Task.Delay(3000, cancellation);
            }
        }
    }
}
