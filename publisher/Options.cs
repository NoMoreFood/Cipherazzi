namespace Cipherazzi.Publisher;

[Flags]
internal enum EventKinds { Connections = 1, Endpoints = 2, Health = 4, Policies = 8, All = 7 }

internal sealed class Options
{
    public string Source { get; private set; } = "";
    public Uri? Syslog { get; private set; }
    public bool WindowsEvents { get; private set; }
    public string WindowsSource { get; private set; } = "Cipherazzi";
    public string MessageFile { get; private set; } =
        Path.Combine(AppContext.BaseDirectory, "Cipherazzi.Collector.exe");
    public string? CertificateAuthority { get; private set; }
    public string? ClientCertificate { get; private set; }
    public string CertificateStore { get; private set; } = "CurrentUser";
    public EventKinds Events { get; private set; } = EventKinds.All;
    public string? PolicyFile { get; private set; }
    public string PolicyResults { get; private set; } = "all";
    public int PollMilliseconds { get; private set; } = 1000;
    public int HealthSeconds { get; private set; } = 60;
    public int Rate { get; private set; } = 250;
    public int Facility { get; private set; } = 16;
    public int DurationSeconds { get; private set; }
    public bool Once { get; private set; }
    public bool StartNow { get; private set; }
    public bool Unregister { get; private set; }
    public bool RegisterSource { get; private set; }
    public bool Help { get; private set; }

    public static Options Parse(string[] args)
    {
        var result = new Options();
        var plaintext = false;
        var eventsSpecified = false;
        for (var index = 0; index < args.Length; index++)
        {
            string Value() => ++index < args.Length ? args[index] :
                throw new ArgumentException("Missing option value.");
            int Number(int minimum, int maximum)
            {
                if (!int.TryParse(Value(), out var value) || value < minimum || value > maximum)
                    throw new ArgumentException($"Option must be between {minimum} and {maximum}.");
                return value;
            }
            switch (args[index])
            {
                case "--source": result.Source = Path.GetFullPath(Value()); break;
                case "--syslog": result.Syslog = new Uri(Value(), UriKind.Absolute); break;
                case "--windows-events": result.WindowsEvents = true; break;
                case "--windows-event-source": result.WindowsSource = Value(); break;
                case "--event-message-file": result.MessageFile = Path.GetFullPath(Value()); break;
                case "--syslog-ca": result.CertificateAuthority = Path.GetFullPath(Value()); break;
                case "--client-certificate": result.ClientCertificate = Value().Replace(" ", ""); break;
                case "--certificate-store": result.CertificateStore = Value(); break;
                case "--poll-ms": result.PollMilliseconds = Number(100, 10000); break;
                case "--health-seconds": result.HealthSeconds = Number(5, 3600); break;
                case "--max-events-per-second": result.Rate = Number(1, 10000); break;
                case "--facility": result.Facility = Number(0, 23); break;
                case "--policies": result.PolicyFile = Path.GetFullPath(Value()); break;
                case "--policy-results": result.PolicyResults = Value(); break;
                case "--duration": result.DurationSeconds = Number(1, 86400); break;
                case "--events":
                    eventsSpecified = true;
                    result.Events = 0;
                    foreach (var kind in Value().Split(',', StringSplitOptions.TrimEntries))
                        result.Events |= kind switch
                        {
                            "connections" => EventKinds.Connections, "endpoints" => EventKinds.Endpoints,
                            "health" => EventKinds.Health, "policies" => EventKinds.Policies,
                            _ => throw new ArgumentException("Unknown event kind.")
                        };
                    break;
                case "--allow-plaintext-syslog": plaintext = true; break;
                case "--once": result.Once = true; break;
                case "--start-now": result.StartNow = true; break;
                case "--unregister": result.Unregister = true; break;
                case "--register-event-source": result.RegisterSource = true; break;
                case "--help" or "-h": result.Help = true; break;
                default: throw new ArgumentException("Unknown option: " + args[index]);
            }
        }
        if (result.Help)
            return result;

        // Policy evaluation is enabled explicitly and shares the snapshot delivery cursor.
        if (result.PolicyFile is not null && !eventsSpecified)
            result.Events |= EventKinds.Policies;
        if (result.PolicyResults is not ("all" or "nonpassing" or "violations") ||
            result.Events.HasFlag(EventKinds.Policies) && result.PolicyFile is null)
            throw new ArgumentException(
                "Policy events require --policies; use --policy-results all, nonpassing, or violations.");

        // Require an explicit transport and preserve normal certificate and hostname validation.
        if (result.Syslog is { } uri && (uri.Scheme is not ("tls" or "tcp") || uri.Host.Length == 0 ||
            uri.UserInfo.Length != 0 || uri.AbsolutePath != "/" || uri.Query.Length != 0 ||
            uri.Fragment.Length != 0 || uri.Port == 0 || uri.Scheme == "tcp" && !plaintext))
            throw new ArgumentException("Use tls://host:6514; plaintext tcp:// requires --allow-plaintext-syslog.");
        if (result.CertificateStore != "CurrentUser" ||
            result.ClientCertificate is { } thumbprint &&
                (thumbprint.Length is not (40 or 64) || thumbprint.Any(value => !Uri.IsHexDigit(value))))
            throw new ArgumentException(
                "Use the running account's CurrentUser certificate store and a hexadecimal thumbprint.");
        if ((result.CertificateAuthority is not null || result.ClientCertificate is not null) &&
            result.Syslog?.Scheme != "tls")
            throw new ArgumentException("Certificate options require a TLS syslog destination.");
        if (result.WindowsSource.Length is 0 or > 64 ||
            result.WindowsSource.Any(value => !char.IsAsciiLetterOrDigit(value) && value is not ('-' or '_' or '.')))
            throw new ArgumentException(
                "Use a Windows event source of at most 64 letters, digits, dots, dashes, or underscores.");
        if (result.RegisterSource && (result.Source.Length != 0 || result.Syslog is not null ||
            result.WindowsEvents || result.Unregister || result.Once || result.StartNow ||
            result.DurationSeconds != 0 || result.PolicyFile is not null))
            throw new ArgumentException("Register the Windows event source as a separate operation.");
        if (!result.RegisterSource && (result.Source.Length == 0 || result.Syslog is null && !result.WindowsEvents))
            throw new ArgumentException("Choose --source and at least one publishing destination.");
        return result;
    }

    public static void PrintHelp() => Console.WriteLine("""
        Cipherazzi.Publisher --source capture.db --syslog tls://siem.example:6514 [--windows-events]
        Cipherazzi.Publisher --source capture.db --windows-events [--once]
        Cipherazzi.Publisher --register-event-source [--event-message-file Cipherazzi.Collector.exe]

          --events connections,endpoints,health,policies  Choose event kinds (default metadata and health)
          --policies <file.config>              Evaluate the viewer's exported policies in the background
          --policy-results all|nonpassing|violations  Choose policy outcomes (default all, including recovery)
          --config <file>                       Load JSON command options; paths resolve beside the file
          --service                             Run through Windows Services
          --poll-ms <100..10000>                 Journal poll interval (default 1000 ms)
          --health-seconds <5..3600>             Health snapshot interval (default 60 seconds)
          --max-events-per-second <1..10000>     Per-destination rate limit (default 250)
          --facility <0..23>                    Syslog facility (default 16, local0)
          --syslog-ca <file>                    PEM/DER CA for a private syslog trust chain
          --client-certificate <thumbprint>     Optional TLS client certificate with private key
          --certificate-store CurrentUser      Use the running account's personal certificate store
          --allow-plaintext-syslog              Explicitly allow tcp://host:514; UDP is unsupported
          --windows-event-source <name>         Registered Application source (default Cipherazzi)
          --once                               Catch up and exit; a failed destination returns failure
          --duration <1..86400>                 Stop a continuous publisher after this many seconds
          --start-now                          Start a new destination at the current journal revision
          --unregister                         Remove selected publishing cursors and retention protection
          --help / -h                          Print usage

        Windows source registration requires elevation and a collector binary containing message resources.
        Publishing requires write access to the journal for durable cursors. Destinations retry independently.
        First use publishes available history unless --start-now is supplied; subsequent runs resume.
        Events are latest committed snapshots, not an immutable history of every intermediate change.
        Policies load at startup and apply to subsequent unread snapshots; policy events use Windows ID 1004.
        Syslog transport writes have no receiver acknowledgement; interruptions can duplicate events.
        Published metadata excludes public certificate DER, packet payloads, and private keys.
        Stop with Ctrl+C. Publishing is disabled unless this application is explicitly run.
        """);
}
