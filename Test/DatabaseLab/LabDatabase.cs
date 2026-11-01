using System.Data.Common;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

// Shared fixtures for checks that need a private journal copy or a disposable server database.
internal static class LabDatabase
{
    private static (DbConnectionStringBuilder Builder, string Key) Catalog(DatabaseSource target) =>
        target.Provider == DatabaseProvider.SqlServer ?
            (new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(target.ConnectionString), "Initial Catalog") :
            (new Npgsql.NpgsqlConnectionStringBuilder(target.ConnectionString), "Database");

    private static void Administer(DatabaseSource target, DbConnectionStringBuilder builder, string key, string sql)
    {
        builder[key] = target.Provider == DatabaseProvider.SqlServer ? "master" : "postgres";
        using var connection = new DatabaseSource(target.Provider, builder.ConnectionString).CreateConnection();
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    // Creates an empty database on the target's server and returns a source that connects to it.
    public static DatabaseSource CreateServerDatabase(DatabaseSource target, string name)
    {
        var (builder, key) = Catalog(target);
        Administer(target, builder, key, target.Provider == DatabaseProvider.SqlServer ?
            $"CREATE DATABASE [{name}]" : $"CREATE DATABASE \"{name}\"");
        builder[key] = name;
        return new(target.Provider, builder.ConnectionString);
    }

    // Drops a database created for a lab run after closing its other sessions.
    public static void DropServerDatabase(DatabaseSource database)
    {
        var (builder, key) = Catalog(database);
        var name = builder[key].ToString()!;
        if (!name.StartsWith("Cipherazzi", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected test database name.");
        Administer(database, builder, key, database.Provider == DatabaseProvider.SqlServer ?
            $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]" :
            $"DROP DATABASE \"{name}\" WITH (FORCE)");
    }

    // Returns the open copy; pooling stays off so the file can be replaced or removed after disposal.
    public static SqliteConnection CopySqlite(string source, string destination)
    {
        using var original = (SqliteConnection)DatabaseSource.Sqlite(source).CreateConnection();
        var copy = new SqliteConnection($"Data Source={destination};Pooling=False");
        try
        {
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
            return copy;
        }
        catch
        {
            copy.Dispose();
            throw;
        }
    }
}
