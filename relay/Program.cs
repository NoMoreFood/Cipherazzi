using Cipherazzi.Data;
using System.Data.Common;

if (Cipherazzi.Relay.ConnectionProvisioning.Run(args) is { } provisioned)
    return provisioned;
return Cipherazzi.Deployment.Deployment.Run("CipherazziRelay", args,
    (options, cancellation) => RunAsync(options, cancellation).GetAwaiter().GetResult());

static async Task<int> RunAsync(string[] args, CancellationToken cancellation)
{
    SQLitePCL.Batteries_V2.Init();
    using var shutdown = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; shutdown.Cancel(); };
    try
    {
        string? source = null;
        string? provider = null;
        string? credentialFile = null;
        var once = false;
        for (var index = 0; index < args.Length; ++index)
        {
            string Value() => ++index < args.Length ? args[index] :
                throw new ArgumentException("Missing option value.");
            switch (args[index])
            {
                case "--source": source = Value(); break;
                case "--provider": provider = Value(); break;
                case "--connection-file": credentialFile = Value(); break;
                case "--connection-env":
                    throw new ArgumentException("Use --connection-file with an account-protected connection.");
                case "--once": once = true; break;
                case "--help":
                    Console.WriteLine("""
                        Cipherazzi.Relay --source capture.db --provider sqlserver|postgresql [--once]
                                          --connection-file connection.credential
                                          [--config file.json] [--service]

                        Cipherazzi.Relay --protect-connection connection.credential --provider sqlserver|postgresql
                                          [--local-system]

                        Provision a connection for the running account; --local-system requires elevation and
                        protects it for the service account. Connection input is hidden and never written as plaintext.
                        Other service accounts must provision their connection while running as that account.
                        The destination database must already exist. The relay creates its tables in the
                        cipherazzi schema.
                        Leave running to stream committed metadata; --once catches up and exits.
                        A durable destination cursor resumes interrupted transfers without duplicate flows.
                        The relay needs write access to the local journal to register its durable acknowledgement.
                        Automatic retention preserves pending uploads for every registered destination.
                        Use collector --replication-required to protect data before the first relay starts.
                        Stop with Ctrl+C.
                        """);
                    return 0;
                default: throw new ArgumentException("Unknown option: " + args[index]);
            }
        }
        if (source is null || provider is null || credentialFile is null)
            throw new ArgumentException("Supply --source, --provider, and --connection-file. Use --help for details.");
        var target = ConnectionCredentials.Load(credentialFile);
        if (provider != (target.Provider == DatabaseProvider.SqlServer ? "sqlserver" : "postgresql"))
            throw new ArgumentException("The provider does not match the protected connection.");
        var initialized = false;
        var retry = false;
        long transferred = 0;
        var report = DateTime.UtcNow;
        while (!shutdown.IsCancellationRequested)
        {
            try
            {
                if (!initialized)
                {
                    await Replication.RegisterAsync(Path.GetFullPath(source), target, shutdown.Token);
                    await Replication.InitializeAsync(target, shutdown.Token);
                    initialized = true;
                    Console.WriteLine("Connected: " + target.DisplayName);
                }
                var result = await Replication.SyncAsync(Path.GetFullPath(source), target, shutdown.Token);
                transferred += result.Connections;
                if (retry || once || DateTime.UtcNow - report > TimeSpan.FromSeconds(5))
                {
                    Console.WriteLine($"Revision {result.Revision}; {transferred:N0} observation updates transferred.");
                    retry = false;
                    report = DateTime.UtcNow;
                }
                if (once && !result.More)
                    return 0;
                if (!result.More)
                    await Task.Delay(200, shutdown.Token);
            }
            catch (Exception error) when (!once && !shutdown.IsCancellationRequested &&
                error is not ArgumentException and not InvalidDataException)
            {
                if (!retry)
                    Console.Error.WriteLine("Replication interrupted; the local journal is retained. " + error.Message);
                retry = true;
                initialized = false;
                await Task.Delay(3000, shutdown.Token);
            }
        }
        return 0;
    }
    catch (Exception error) when (shutdown.IsCancellationRequested &&
        error is OperationCanceledException or DbException)
    {
        return 0;
    }
    catch (Exception error)
    {
        Console.Error.WriteLine(error.Message);
        return 1;
    }
}
