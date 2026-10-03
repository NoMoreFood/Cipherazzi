using System.Data;
using System.Data.Common;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;

namespace Cipherazzi.Data;

public enum DatabaseProvider { Sqlite, SqlServer, PostgreSql }

public sealed record DatabaseSource
{
    private readonly string? localConnection;
    private static readonly Lazy<Dictionary<Rune, string>> caseVariants = new(() =>
    {
        // Derive literal case alternatives from the same invariant rules as local journal searches.
        var groups = new Dictionary<Rune, StringBuilder>();
        for (var scalar = 0; scalar <= 0x10ffff; scalar++)
        {
            if (!Rune.IsValid(scalar))
                continue;
            var value = new Rune(scalar);
            var lower = Rune.ToLowerInvariant(value);
            if (value == lower)
                continue;
            if (!groups.TryGetValue(lower, out var group))
                groups[lower] = group = new StringBuilder();
            group.Append(value.ToString());
        }
        return groups.ToDictionary(pair => pair.Key, pair => pair.Value.ToString());
    });
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
            DataSource = Path.GetFullPath(path),
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 2
        }.ToString());

    public string Prefix => Provider == DatabaseProvider.Sqlite ? "" : "cipherazzi.";
    public string FilePath => Provider == DatabaseProvider.Sqlite ?
        new SqliteConnectionStringBuilder(ConnectionString).DataSource : "";
    public string DisplayName { get; }

    internal string JsonText(string key) => JsonValue(key == "http_host" ?
        JsonWithProperty("c.crypto_json", key) : "c.crypto_json", key);

    internal string TextEquals(DbCommand command, string expression, string parameter, string literal) =>
        Provider == DatabaseProvider.Sqlite ? $"cipherazzi_lower({expression})=cipherazzi_lower({parameter})" :
            ServerMatch(command, [expression], parameter, literal, false, true);

    internal string TextMatch(DbCommand command, string expression, string parameter, string literal,
        bool prefix = false) => TextMatch(command, [expression], parameter, literal, prefix);

    internal string TextMatch(DbCommand command, IReadOnlyList<string> expressions, string parameter, string literal,
        bool prefix = false)
    {
        if (Provider != DatabaseProvider.Sqlite)
            return ServerMatch(command, expressions, parameter, literal, prefix, false);
        var sqlite = (SqliteConnection)command.Connection!;

        // Bound callback arguments and skip groups whose fields are all shorter than the search text.
        if (expressions.Count > 4)
            return "(" + string.Join(" OR ", expressions.Chunk(4).Select(fields =>
                TextMatch(command, fields, parameter, literal, prefix))) + ")";

        // Fold the bound UTF-8 literal once instead of returning normalized SQL text for every field.
        var text = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(literal)).ToLowerInvariant();
        var ascii = Ascii.IsValid(text);
        var pattern = Encoding.UTF8.GetBytes(text);
        var function = "cipherazzi_match_" + parameter.TrimStart('@');
        var status = SQLitePCL.raw.sqlite3_create_function(sqlite.Handle, function, expressions.Count,
            SQLitePCL.raw.SQLITE_UTF8 | SQLitePCL.raw.SQLITE_DETERMINISTIC, null, (context, _, values) =>
        {
            // Inspect SQLite's UTF-8 buffer directly; only Unicode folding needs a managed string.
            var observed = false;
            foreach (var field in values)
            {
                if (SQLitePCL.raw.sqlite3_value_type(field) == SQLitePCL.raw.SQLITE_NULL)
                    continue;
                observed = true;
                var utf8 = SQLitePCL.raw.sqlite3_value_text(field);
                var value = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(in utf8.GetPinnableReference()),
                    SQLitePCL.raw.sqlite3_value_bytes(field));
                var nul = value.IndexOf((byte)0);
                if (nul >= 0)
                    value = value[..nul];
                if (ascii && value.Length < pattern.Length)
                    continue;
                var match = false;
                if (ascii && Ascii.IsValid(value))
                {
                    if (pattern.Length == 0)
                        match = true;
                    else if (prefix)
                        match = value.Length >= pattern.Length &&
                            Ascii.EqualsIgnoreCase(value[..pattern.Length], pattern);
                    else
                    {
                        var first = pattern[0];
                        var upper = first is >= (byte)'a' and <= (byte)'z' ? (byte)(first - 32) : first;
                        while (value.Length >= pattern.Length)
                        {
                            var index = value[..(value.Length - pattern.Length + 1)].IndexOfAny(first, upper);
                            if (index < 0)
                                break;
                            value = value[index..];
                            if (Ascii.EqualsIgnoreCase(value[..pattern.Length], pattern))
                            {
                                match = true;
                                break;
                            }
                            value = value[1..];
                        }
                    }
                }
                else
                {
                    var folded = Encoding.UTF8.GetString(value).ToLowerInvariant();
                    match = prefix ? folded.StartsWith(text, StringComparison.Ordinal) :
                        folded.Contains(text, StringComparison.Ordinal);
                }
                if (match)
                {
                    SQLitePCL.raw.sqlite3_result_int(context, 1);
                    return;
                }
            }
            if (observed)
                SQLitePCL.raw.sqlite3_result_int(context, 0);
            else
                SQLitePCL.raw.sqlite3_result_null(context);
        });
        if (status != SQLitePCL.raw.SQLITE_OK)
            throw new SqliteException("Unable to prepare text matching.", status);
        var minimum = text.EnumerateRunes().Count();
        return "CASE WHEN " + string.Join(" OR ", expressions.Select(expression =>
            $"length({expression})>={minimum}")) + $" THEN {function}({string.Join(',', expressions)}) ELSE 0 END";
    }

    private string ServerMatch(DbCommand command, IReadOnlyList<string> expressions, string parameter,
        string literal, bool prefix, bool exact)
    {
        var bound = parameter + "_literal";
        var upper = parameter + "_upper";
        var lower = parameter + "_lower";
        var minimum = parameter + "_minimum";
        var text = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(literal)).ToLowerInvariant();
        var binaryPattern = Provider == DatabaseProvider.SqlServer && text.EnumerateRunes().All(value =>
            !caseVariants.Value.TryGetValue(value, out var group) || value.Value <= char.MaxValue &&
                !group.Any(char.IsSurrogate));
        if (!command.Parameters.Contains(bound))
        {
            // Fold only characters that can match the literal; full Unicode maps are costly for every field.
            var variants = new StringBuilder();
            var replacements = new StringBuilder();
            foreach (var value in text.EnumerateRunes().Distinct())
            {
                if (!caseVariants.Value.TryGetValue(value, out var group))
                    continue;
                foreach (var alternative in group.EnumerateRunes())
                {
                    variants.Append(alternative.ToString());
                    replacements.Append(value.ToString());
                }
            }
            AddParameter(command, upper, variants.ToString());
            AddParameter(command, lower, replacements.ToString());
            AddParameter(command, minimum, text.EnumerateRunes().Count());
            if (binaryPattern)
            {
                // BMP alternatives occupy one UTF-16 code unit; supplementary case pairs use translation.
                var pattern = new StringBuilder(prefix || exact ? "" : "%");
                foreach (var value in text.EnumerateRunes())
                    if (caseVariants.Value.TryGetValue(value, out var group))
                        pattern.Append('[').Append(value.ToString()).Append(group).Append(']');
                    else
                        pattern.Append(InvestigationSql.Escape(value.ToString()));
                pattern.Append(exact ? '\u0001' : '%');
                AddParameter(command, bound, pattern.ToString());
            }
            else
                AddParameter(command, bound, exact ? text :
                    (prefix ? "" : "%") + InvestigationSql.Escape(text) + "%");
        }

        // UTF-8 binary translation preserves supplementary scalars and avoids linguistic normalization.
        static string Utf8(string value) =>
            $"CONVERT(varchar(max),({value}) COLLATE Latin1_General_100_BIN2_UTF8)";
        var translate = ((string)command.Parameters[upper].Value!).Length > 0;
        var utf8Server = command.Connection is NpgsqlConnection postgres &&
            postgres.PostgresParameters.TryGetValue("server_encoding", out var encoding) && encoding == "UTF8";
        return "(" + string.Join(" OR ", expressions.Select(expression =>
        {
            if (Provider == DatabaseProvider.PostgreSql)
            {
                var value = $"({expression}) COLLATE pg_catalog.\"C\"";
                if (translate)
                {
                    var translated = $"TRANSLATE({value},{upper},{lower})";
                    value = utf8Server ? $"CASE WHEN OCTET_LENGTH({expression})=CHAR_LENGTH({expression}) " +
                        $"THEN LOWER({value}) ELSE {translated} END" : translated;
                }
                var match = exact ? $"{value}={bound}" : $"{value} LIKE {bound} ESCAPE '\\'";
                return $"CASE WHEN CHAR_LENGTH({expression})>={minimum} THEN " +
                    $"CASE WHEN {match} THEN 1 ELSE 0 END ELSE 0 END=1";
            }
            string predicate;
            var unicode = $"CONVERT(nvarchar(max),({expression}))";
            if (binaryPattern)
                predicate = $"({unicode}{(exact ? "+NCHAR(1)" : "")}) COLLATE Latin1_General_100_BIN2 " +
                    $"LIKE {bound} COLLATE Latin1_General_100_BIN2 ESCAPE '\\'";
            else
            {
                var input = Utf8(expression);

                // ASCII text uses ordinary casing without building a translation table per row.
                var folded = translate ? $"CASE WHEN DATALENGTH({expression})=2*DATALENGTH({input}) " +
                    $"THEN LOWER({input}) ELSE TRANSLATE({input},{Utf8(upper)},{Utf8(lower)}) END" : input;
                predicate = exact ? $"CONVERT(varbinary(max),{folded})=CONVERT(varbinary(max),{Utf8(bound)})" :
                    $"{folded} LIKE {Utf8(bound)} ESCAPE '\\'";
            }
            return $"CASE WHEN DATALENGTH({unicode})>=2*{minimum} THEN " +
                $"CASE WHEN {predicate} THEN 1 ELSE 0 END ELSE 0 END=1";
        })) + ")";
    }

    internal string JsonHasEscapes(string expression) => Provider switch
    {
        DatabaseProvider.SqlServer => $"CHARINDEX('\\',({expression}) COLLATE Latin1_General_100_BIN2)>0",
        DatabaseProvider.PostgreSql => $"STRPOS({expression},'\\')>0",
        _ => $"INSTR({expression},'\\')>0"
    };

    internal string JsonWithProperty(string expression, string key) => Provider switch
    {
        DatabaseProvider.SqlServer => $"CASE WHEN {JsonHasEscapes(expression)} OR " +
            $"CHARINDEX('\"{key}\"',({expression}) COLLATE Latin1_General_100_BIN2)>0 " +
            $"THEN {expression} ELSE '{{}}' END",
        DatabaseProvider.PostgreSql => $"CASE WHEN {JsonHasEscapes(expression)} OR " +
            $"STRPOS({expression},'\"{key}\"')>0 THEN {expression} ELSE '{{}}' END",
        _ => expression
    };

    internal string JsonValue(string column, string key) => Provider switch
    {
        DatabaseProvider.SqlServer => $"JSON_VALUE({column},'$.{key}')",
        DatabaseProvider.PostgreSql => key.Contains('.') ?
            $"({column}::jsonb#>>'{{{key.Replace('.', ',')}}}')" : $"({column}::jsonb->>'{key}')",
        _ => $"json_extract({column},'$.{key}')"
    };

    internal string SafeJson(string column) => Provider switch
    {
        DatabaseProvider.SqlServer => $"CASE WHEN ISJSON({column})=1 AND " +
            $"LEFT(TRIM(NCHAR(9)+NCHAR(10)+NCHAR(13)+N' ' FROM {column}),1)=N'{{' THEN {column} END",
        DatabaseProvider.PostgreSql => $"CASE WHEN pg_input_is_valid({column},'jsonb') " +
            $"THEN CASE WHEN jsonb_typeof(({column})::jsonb)='object' THEN {column} END END",
        _ => $"CASE WHEN json_valid({column}) THEN CASE WHEN json_type({column})='object' " +
            $"THEN {column} END END"
    };

    internal string JsonScalar(string column, string key, bool integer = false,
        long minimum = long.MinValue, long maximum = long.MaxValue)
    {
        // Only a single field of the expected JSON type can identify an association or operation timestamp.
        var split = key.LastIndexOf('.');
        var parent = split < 0 ? "" : key[..split];
        var field = split < 0 ? key : key[(split + 1)..];
        var document = SafeJson(column);
        var path = parent.Length == 0 ? "" : $",'$.{parent}'";
        var bounds = FormattableString.Invariant($"{minimum} AND {maximum}");
        if (Provider == DatabaseProvider.SqlServer)
        {
            var value = integer ? "TRY_CONVERT(bigint,[value])" : "[value]";
            var condition = integer ? $"[type]=2 AND {value} BETWEEN {bounds}" : "[type]=1";
            return $"(SELECT CASE WHEN COUNT(*)=1 THEN MAX(CASE WHEN {condition} THEN {value} END) END " +
                $"FROM OPENJSON({document}{path}) WHERE {JsonKeyEquals("[key]", field)})";
        }
        if (Provider == DatabaseProvider.PostgreSql)
        {
            var container = parent.Length == 0 ? $"({document})::json" :
                $"(({document})::json#>'{{{parent.Replace('.', ',')}}}')";
            container = $"CASE WHEN json_typeof({container})='object' THEN {container} ELSE '{{}}'::json END";
            var number = "(value::text)::bigint";
            var value = integer ? $"CASE WHEN pg_input_is_valid(value::text,'bigint') " +
                $"THEN {number} END" : "(value#>>'{}')";
            var condition = integer ? $"json_typeof(value)='number' AND {value} BETWEEN {bounds}" :
                "json_typeof(value)='string'";
            return $"(SELECT CASE WHEN COUNT(*)=1 THEN MAX(CASE WHEN {condition} THEN {value} END) END " +
                $"FROM json_each({container}) WHERE key='{field}')";
        }
        var sqliteCondition = integer ? $"type='integer' AND typeof(atom)='integer' " +
            $"AND atom BETWEEN {bounds}" : "type='text'";
        return $"(SELECT CASE WHEN COUNT(*)=1 THEN MAX(CASE WHEN {sqliteCondition} THEN atom END) END " +
            $"FROM json_each({document}{path}) WHERE key='{field}')";
    }

    // SQL string equality pads trailing spaces; JSON member names require an exact binary value and byte length.
    internal string JsonKeyEquals(string expression, string name) => Provider == DatabaseProvider.SqlServer ?
        $"({expression} COLLATE Latin1_General_100_BIN2=N'{name}' AND DATALENGTH({expression})={name.Length * 2})" :
        $"{expression}='{name}'";

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

    internal DbTransaction BeginRead(DbConnection connection, CancellationToken cancellation) =>
        connection is SqliteConnection sqlite ? sqlite.BeginTransaction(deferred: true) :
        connection.BeginTransactionAsync(Provider == DatabaseProvider.SqlServer ?
            IsolationLevel.Snapshot : IsolationLevel.RepeatableRead, cancellation).GetAwaiter().GetResult();

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
