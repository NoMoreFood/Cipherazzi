using System.Data.Common;
using System.Text.Json.Serialization;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

namespace Cipherazzi.Data;

public enum DatabaseProvider { Sqlite, SqlServer, PostgreSql }

public sealed record DatabaseSource
{
    private readonly string? localConnection;
    internal byte[] ProtectedConnection { get; } = [];
    public DatabaseProvider Provider { get; }
    public string CacheKey { get; } = Guid.NewGuid().ToString("N");
    [JsonIgnore]
    public string ConnectionString
    {
        get
        {
            if (Provider == DatabaseProvider.Sqlite)
                return localConnection!;
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Protected server connections require Windows.");
            return ConnectionCredentials.Unprotect(Provider, ProtectedConnection);
        }
    }

    public DatabaseSource(DatabaseProvider provider, string connectionString)
    {
        Provider = provider;
        if (provider == DatabaseProvider.Sqlite)
        {
            localConnection = connectionString;
            DisplayName = FilePath;
            return;
        }
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Protected server connections require Windows.");
        if (provider is not (DatabaseProvider.SqlServer or DatabaseProvider.PostgreSql))
            throw new ArgumentException("Choose SQL Server or PostgreSQL.");

        // Retain only the protected connection and public display details between database operations.
        DisplayName = provider == DatabaseProvider.SqlServer ?
            "SQL Server · " + new SqlConnectionStringBuilder(connectionString).DataSource + " / " +
                new SqlConnectionStringBuilder(connectionString).InitialCatalog :
            "PostgreSQL · " + new NpgsqlConnectionStringBuilder(connectionString).Host + " / " +
                new NpgsqlConnectionStringBuilder(connectionString).Database;
        ProtectedConnection = ConnectionCredentials.Protect(provider, connectionString);
    }

    public override string ToString() => DisplayName;

    public static DatabaseSource Sqlite(string path) => new(DatabaseProvider.Sqlite,
        new SqliteConnectionStringBuilder
        {
            DataSource = Path.GetFullPath(path), Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private, Pooling = false, DefaultTimeout = 2
        }.ToString());

    public string Prefix => Provider == DatabaseProvider.Sqlite ? "" : "cipherazzi.";
    public string FilePath => Provider == DatabaseProvider.Sqlite ?
        new SqliteConnectionStringBuilder(ConnectionString).DataSource : "";
    public string DisplayName { get; }

    internal string JsonText(string key) => JsonValue("c.crypto_json", key);

    // Fold fields and bound values with the same text rules, independently of PostgreSQL's database locale.
    internal string LowerText(string expression) => Provider switch
    {
        DatabaseProvider.Sqlite => $"cipherazzi_lower({expression})",
        DatabaseProvider.PostgreSql => $"LOWER(({expression}) COLLATE pg_catalog.pg_c_utf8)",
        _ => $"LOWER({expression})"
    };

    internal string TextMatch(string expression, string parameter) =>
        $"{LowerText(expression)} LIKE {LowerText(parameter)} ESCAPE '\\'";

    internal string JsonValue(string column, string key) => Provider switch
    {
        DatabaseProvider.SqlServer => $"JSON_VALUE({column},'$.{key}')",
        DatabaseProvider.PostgreSql => key.Contains('.') ?
            $"({column}::jsonb#>>'{{{key.Replace('.', ',')}}}')" : $"({column}::jsonb->>'{key}')",
        _ => $"json_extract({column},'$.{key}')"
    };

    public DbConnection CreateConnection() => Provider switch
    {
        DatabaseProvider.Sqlite => new SqliteConnection(ConnectionString),
        DatabaseProvider.SqlServer => new SqlConnection(ConnectionString),
        _ => new NpgsqlConnection(ConnectionString)
    };

    public async Task<DbConnection> OpenConnectionAsync(CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        var connection = CreateConnection();
        Task? opening = null;
        try
        {
            opening = connection.OpenAsync(cancellation);
            await opening.WaitAsync(cancellation).ConfigureAwait(false);
            if (connection is SqliteConnection sqlite)
            {
                // Apply the same invariant text matching to Unicode process and provider names.
                sqlite.CreateFunction<string?, string?>("cipherazzi_lower", value => value?.ToLowerInvariant(),
                    isDeterministic: true);
                // Interrupt native scans even when an aggregate has not returned its first managed row.
                if (cancellation.CanBeCanceled)
                    SQLitePCL.raw.sqlite3_progress_handler(sqlite.Handle, 1000,
                        state => ((CancellationToken)state).IsCancellationRequested ? 1 : 0, cancellation);
            }
            return connection;
        }
        catch
        {
            // Some provider negotiation stages ignore cancellation; release them when opening actually finishes.
            if (opening is { IsCompleted: false })
                _ = opening.ContinueWith(completed =>
                {
                    _ = completed.Exception;
                    connection.Dispose();
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            else
                connection.Dispose();
            throw;
        }
    }

    public static DatabaseSource FromEnvironment(string provider, string variable)
    {
        var kind = provider.ToLowerInvariant() switch
        {
            "sqlserver" or "mssql" => DatabaseProvider.SqlServer,
            "postgresql" or "postgres" => DatabaseProvider.PostgreSql,
            _ => throw new ArgumentException("Choose sqlserver or postgresql.")
        };
        var connection = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrWhiteSpace(connection))
            throw new ArgumentException($"Set the {variable} environment variable to the connection string.");
        return new DatabaseSource(kind, connection);
    }

    public static void AddParameter(DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }

    public void Validate(DbConnection connection, CancellationToken cancellation = default)
    {
        using var command = connection.CreateCommand();
        command.CommandTimeout = Provider == DatabaseProvider.Sqlite ? 2 : 5;
        cancellation.ThrowIfCancellationRequested();
        if (Provider == DatabaseProvider.Sqlite)
        {
            command.CommandText = "PRAGMA application_id";
            if (Convert.ToInt64(command.ExecuteScalarAsync(cancellation).GetAwaiter().GetResult()) != 0x435A5A49)
                throw new InvalidDataException("Choose a database created by the Cipherazzi collector.");
            command.CommandText = "PRAGMA trusted_schema=OFF";
            cancellation.ThrowIfCancellationRequested();
            command.ExecuteNonQueryAsync(cancellation).GetAwaiter().GetResult();
        }
        cancellation.ThrowIfCancellationRequested();
        command.CommandText = $"SELECT schema_version FROM {Prefix}metadata WHERE id=1";
        if (Convert.ToInt64(command.ExecuteScalarAsync(cancellation).GetAwaiter().GetResult()) != 4)
            throw new InvalidDataException("This database schema is not supported. Use a new collector database.");
    }
}
