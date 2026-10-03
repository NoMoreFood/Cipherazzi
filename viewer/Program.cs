namespace Cipherazzi.Viewer;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        SQLitePCL.Batteries_V2.Init();
        try
        {
            var positional = new List<string>();
            var verify = false;
            var smoke = false;
            string? provider = null;
            string? configuration = null;
            string? credentialFile = null;
            for (var index = 0; index < args.Length; ++index)
            {
                string Value() => ++index < args.Length ? args[index] : throw new ArgumentException("Missing option value.");
                switch (args[index])
                {
                    case "--provider": provider = Value(); break;
                    case "--connection-file": credentialFile = Value(); break;
                    case "--connection-env":
                        throw new ArgumentException("Use --connection-file with an account-protected connection.");
                    case "--config": configuration = Value(); break;
                    case "--verify": verify = true; break;
                    case "--verify-ui": smoke = true; break;
                    default: positional.Add(args[index]); break;
                }
            }
            var source = credentialFile is not null ? ConnectionCredentials.Load(credentialFile) :
                provider is not null ? throw new ArgumentException("Supply --connection-file for a server database.") :
                positional.Count != 0 ? DatabaseSource.Sqlite(positional[0]) : null;
            if (provider is not null && provider !=
                (source?.Provider == DatabaseProvider.SqlServer ? "sqlserver" : "postgresql"))
                throw new ArgumentException("The provider does not match the protected connection.");
            if (verify)
            {
                var snapshot = Database.Read(source ?? throw new ArgumentException("Choose a database."),
                    new Query("", "", false, PageCursor.Newest), CancellationToken.None);
                Console.WriteLine($"Read {snapshot.Rows.Count} rows. {snapshot.Health}");
                return 0;
            }
            var settings = ViewerSettings.Load(configuration);
            ApplicationConfiguration.Initialize();
            UiTheme.Select(settings.Theme);
            using var window = new MainForm(source, smoke ? positional.Last() : null, settings);
            Application.Run(window);
            return window.ExitCode;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }
}
