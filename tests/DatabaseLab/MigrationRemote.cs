using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.SqlClient;
using Npgsql;

internal static class MigrationRemote
{
    public static async Task RunAsync(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        var results = new List<object>();
        foreach (var (provider, variable) in new[] { ("sqlserver", "CIPHERAZZI_SQLSERVER"), ("postgresql", "CIPHERAZZI_POSTGRESQL") })
        {
            var source = DatabaseSource.FromEnvironment(provider, variable);
            var name = "CipherazziMigration_" + Guid.NewGuid().ToString("N")[..10];
            DatabaseSource target;
            DatabaseSource admin;
            if (source.Provider == DatabaseProvider.SqlServer)
            {
                var builder = new SqlConnectionStringBuilder(source.ConnectionString) { InitialCatalog = "master" };
                admin = new(source.Provider, builder.ConnectionString);
                builder.InitialCatalog = name;
                target = new(source.Provider, builder.ConnectionString);
            }
            else
            {
                var builder = new NpgsqlConnectionStringBuilder(source.ConnectionString) { Database = "postgres" };
                admin = new(source.Provider, builder.ConnectionString);
                builder.Database = name;
                target = new(source.Provider, builder.ConnectionString);
            }
            var saved = Path.Combine(output, target.Provider + ".credential");
            if (File.Exists(saved))
                target = ConnectionCredentials.Load(saved);
            else
            {
                using var connection = await admin.OpenConnectionAsync(deadline.Token);
                using var command = connection.CreateCommand();
                command.CommandText = provider == "sqlserver" ? $"CREATE DATABASE [{name}]" : $"CREATE DATABASE \"{name}\"";
                await command.ExecuteNonQueryAsync(deadline.Token);
                ConnectionCredentials.Save(saved, target);
            }
            await Replication.InitializeAsync(target, deadline.Token);
            while ((await Replication.SyncAsync(args[0], target, deadline.Token)).More) {}
            Environment.SetEnvironmentVariable("CIPHERAZZI_CONNECTION", target.ConnectionString);
            MigrationFeatures.Run([provider, Path.Combine(output, provider)]);
            results.Add(new { provider, database = target.DisplayName });
        }
        File.WriteAllText(Path.Combine(output, "databases.json"), JsonSerializer.Serialize(results));
    }
}
