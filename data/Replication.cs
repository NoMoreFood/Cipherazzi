using System.Data;
using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Npgsql;
using NpgsqlTypes;

namespace Cipherazzi.Data;

public static class Replication
{
    public static async Task RegisterAsync(string path, DatabaseSource target, CancellationToken cancellation)
        => await AcknowledgeAsync(path, target, 0, cancellation);

    private static async Task AcknowledgeAsync(string path, DatabaseSource target, long revision,
        CancellationToken cancellation)
    {
        // Credentials are excluded: rotation must not create another permanently stalled consumer.
        var identity = target.Provider switch
        {
            DatabaseProvider.SqlServer => new SqlConnectionStringBuilder(target.ConnectionString) is var sql ?
                $"sqlserver|{sql.DataSource.ToLowerInvariant()}|{sql.InitialCatalog}" : "",
            DatabaseProvider.PostgreSql => new NpgsqlConnectionStringBuilder(target.ConnectionString) is var pg ?
                $"postgresql|{(pg.Host ?? "").ToLowerInvariant()}|{pg.Port}|{pg.Database}" : "",
            _ => throw new ArgumentException("Replication requires SQL Server or PostgreSQL.")
        };
        var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        var builder = new SqliteConnectionStringBuilder(DatabaseSource.Sqlite(path).ConnectionString)
            { Mode = SqliteOpenMode.ReadWrite };
        using var connection = new SqliteConnection(builder.ToString());
        await connection.OpenAsync(cancellation);
        DatabaseSource.Sqlite(path).Validate(connection, cancellation);
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS replication_consumers (
                target_id TEXT PRIMARY KEY, acknowledged_revision INTEGER NOT NULL CHECK(acknowledged_revision>=0),
                updated_us INTEGER NOT NULL) STRICT;
            INSERT INTO replication_consumers VALUES(@target,@revision,@time)
            ON CONFLICT(target_id) DO UPDATE SET
                acknowledged_revision=max(acknowledged_revision,excluded.acknowledged_revision),
                updated_us=excluded.updated_us;
            """;
        command.Parameters.AddWithValue("@target", id);
        command.Parameters.AddWithValue("@revision", revision);
        command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
        await command.ExecuteNonQueryAsync(cancellation);
        transaction.Commit();
    }

    private static readonly string[] SessionColumns = (
        "id,started_us,updated_us,stopped_us,source,process_status,status,computer_name," +
        "packets,bytes,capture_lost,queue_lost," +
        "truncated,malformed,fragments,unsupported,flow_limit,reassembly_limit,observations,storage_lost," +
        "process_events_lost,active_flows,buffered_bytes,telemetry_lost,change_revision").Split(',');
    private static readonly string[] ConnectionColumns = (
        "run_id,flow_id,first_us,last_us,source_address,source_port,destination_address,destination_port,ip_version," +
        "tls_version,tls_name,cipher_id,cipher_name,sni,offered_versions,offered_ciphers,offered_alpn,selected_alpn," +
        "state,detail,ech_offered,retry_seen,source_pid,source_process,source_path,source_process_started_us," +
        "source_evidence,source_account,source_account_domain,source_account_sid,destination_pid," +
        "destination_process,destination_path,destination_process_started_us,destination_evidence," +
        "destination_account,destination_account_domain,destination_account_sid," +
        "crypto_json,group_name,key_exchange,encryption,key_bits,hash_name,authentication," +
        "psk_mode,certificate_sha256,hello_latency_us,alert,ended_us,close_reason,change_revision").Split(',');
    private static readonly string[] CertificateColumns = ["sha256", "metadata_json", "der", "change_revision"];
    private static readonly string[] CertificateLinkColumns =
        ["run_id", "flow_id", "role", "chain_index", "sha256", "change_revision"];
    private static readonly string[] EventColumns = (
        "id,run_id,timestamp_us,provider,kind,result,pid,peer,port,protocol,cipher,certificate_id," +
        "detail_json,change_revision").Split(',');
    private static readonly HashSet<string> TextColumns = [
        "id", "run_id", "source", "process_status", "status", "source_address", "destination_address", "tls_name",
        "cipher_name", "sni", "offered_versions", "offered_ciphers", "offered_alpn", "selected_alpn", "state", "detail",
        "source_process", "source_path", "source_evidence", "destination_process", "destination_path",
        "destination_evidence", "crypto_json", "group_name", "key_exchange", "encryption", "hash_name",
        "authentication", "psk_mode", "certificate_sha256", "alert", "close_reason", "sha256", "metadata_json",
        "provider", "kind", "result", "peer", "protocol", "cipher", "certificate_id", "detail_json", "role",
        "computer_name", "source_account", "source_account_domain", "source_account_sid",
        "destination_account", "destination_account_domain", "destination_account_sid"
    ];
    private static readonly HashSet<string> NullableColumns = [
        "stopped_us", "tls_version", "tls_name", "cipher_id", "cipher_name", "source_pid", "source_process_started_us",
        "destination_pid", "destination_process_started_us", "key_bits", "hello_latency_us", "ended_us"
    ];

    public static async Task InitializeAsync(DatabaseSource target, CancellationToken cancellation)
    {
        if (target.Provider == DatabaseProvider.Sqlite)
            throw new ArgumentException("Replication requires SQL Server or PostgreSQL.");
        using var connection = await target.OpenConnectionAsync(cancellation);
        using var transaction = await connection.BeginTransactionAsync(cancellation);
        var sqlServer = target.Provider == DatabaseProvider.SqlServer;
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sqlServer ?
            "IF SCHEMA_ID('cipherazzi') IS NULL EXEC('CREATE SCHEMA cipherazzi');" :
            "CREATE SCHEMA IF NOT EXISTS cipherazzi;";
        await command.ExecuteNonQueryAsync(cancellation);
        string TextType(string name) => sqlServer ? name switch
        {
            "id" or "run_id" or "sha256" => "nvarchar(128)", "role" => "nvarchar(16)",
            "sni" => "nvarchar(253)", _ => "nvarchar(max)"
        } : "text";
        string Definition(string[] columns) => string.Join(",", columns.Select(name =>
            name + " " + (name == "der" ? (sqlServer ? "varbinary(max)" : "bytea") :
                TextColumns.Contains(name) ? TextType(name) : "bigint") +
            (NullableColumns.Contains(name) ? " NULL" : " NOT NULL")));
        string Create(string name, string definition) => sqlServer ?
            $"IF OBJECT_ID('cipherazzi.{name}','U') IS NULL CREATE TABLE cipherazzi.{name}({definition});" :
            $"CREATE TABLE IF NOT EXISTS cipherazzi.{name}({definition});";

        // The dedicated schema keeps application tables separate from existing server data.
        command.CommandText =
            Create("metadata", "id bigint PRIMARY KEY CHECK(id=1),schema_version bigint NOT NULL," +
                "revision bigint NOT NULL") +
            Create("replication_sources", $"source_id {TextType("id")} PRIMARY KEY,revision bigint NOT NULL") +
            Create("capture_sessions", Definition(SessionColumns) + ",PRIMARY KEY(id)") +
            Create("certificates", Definition(CertificateColumns) + ",PRIMARY KEY(sha256)") +
            Create("endpoint_events", Definition(EventColumns) +
                ",PRIMARY KEY(id),FOREIGN KEY(run_id) REFERENCES cipherazzi.capture_sessions(id)") +
            Create("connections", "id bigint " + (sqlServer ? "IDENTITY(1,1)" : "GENERATED ALWAYS AS IDENTITY") +
                " PRIMARY KEY," + Definition(ConnectionColumns) +
                ",UNIQUE(run_id,flow_id),FOREIGN KEY(run_id) REFERENCES cipherazzi.capture_sessions(id)") +
            Create("connection_certificates", Definition(CertificateLinkColumns) +
                ",PRIMARY KEY(run_id,flow_id,role,chain_index)," +
                "FOREIGN KEY(sha256) REFERENCES cipherazzi.certificates(sha256)," +
                "FOREIGN KEY(run_id,flow_id) REFERENCES cipherazzi.connections(run_id,flow_id)") +
            (sqlServer ?
                "IF NOT EXISTS(SELECT 1 FROM cipherazzi.metadata) INSERT INTO cipherazzi.metadata VALUES(1,4,0);" +
                "IF NOT EXISTS(SELECT 1 FROM sys.indexes WHERE name='connections_time' " +
                "AND object_id=OBJECT_ID('cipherazzi.connections')) " +
                "CREATE INDEX connections_time ON cipherazzi.connections(first_us DESC,id DESC);" +
                "IF NOT EXISTS(SELECT 1 FROM sys.indexes WHERE name='connections_changes' " +
                "AND object_id=OBJECT_ID('cipherazzi.connections')) " +
                "CREATE INDEX connections_changes ON cipherazzi.connections(change_revision);" :
                "INSERT INTO cipherazzi.metadata VALUES(1,4,0) ON CONFLICT DO NOTHING;" +
                "CREATE INDEX IF NOT EXISTS connections_time ON cipherazzi.connections(first_us DESC,id DESC);" +
                "CREATE INDEX IF NOT EXISTS connections_changes ON cipherazzi.connections(change_revision);");
        await command.ExecuteNonQueryAsync(cancellation);
        command.CommandText = "SELECT schema_version FROM cipherazzi.metadata WHERE id=1";
        if (Convert.ToInt64(await command.ExecuteScalarAsync(cancellation)) != 4)
            throw new InvalidDataException("The destination schema is not supported.");

        // Cover certificate discovery, endpoint session checks, and the latest collector heartbeat.
        foreach (var (table, name, columns) in new[]
        {
            ("certificates", "certificates_lookup", "change_revision"),
            ("connection_certificates", "connection_certificates_lookup", "change_revision"),
            ("connection_certificates", "connection_certificates_hash", "sha256"),
            ("endpoint_events", "endpoint_events_lookup", "timestamp_us DESC,id DESC"),
            ("endpoint_events", "endpoint_events_run", "run_id"),
            ("capture_sessions", "sessions_time", "started_us DESC")
        })
        {
            command.CommandText = sqlServer ?
                $"IF NOT EXISTS(SELECT 1 FROM sys.indexes WHERE name='{name}' " +
                    $"AND object_id=OBJECT_ID('cipherazzi.{table}')) " +
                    $"CREATE INDEX {name} ON cipherazzi.{table}({columns});" :
                $"CREATE INDEX IF NOT EXISTS {name} ON cipherazzi.{table}({columns});";
            await command.ExecuteNonQueryAsync(cancellation);
        }
        await transaction.CommitAsync(cancellation);
    }

    private static async Task<long> CursorAsync(DbConnection connection, DbTransaction? transaction,
        string databaseId, CancellationToken cancellation)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT revision FROM cipherazzi.replication_sources WHERE source_id=@source";
        DatabaseSource.AddParameter(command, "@source", databaseId);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellation));
    }

    public static async Task<(long Revision, int Connections, bool More)> SyncAsync(string path,
        DatabaseSource target, CancellationToken cancellation)
    {
        await RegisterAsync(path, target, cancellation);
        using var source = (SqliteConnection)await DatabaseSource.Sqlite(path).OpenConnectionAsync(cancellation);
        DatabaseSource.Sqlite(path).Validate(source, cancellation);
        using var read = source.BeginTransaction(deferred: true);
        using var identity = source.CreateCommand();
        identity.Transaction = read;
        identity.CommandText = "SELECT database_id,revision FROM metadata WHERE id=1";
        string databaseId;
        long available;
        using (var reader = await identity.ExecuteReaderAsync(cancellation))
        {
            if (!reader.Read())
                throw new InvalidDataException("The capture journal has no identity.");
            databaseId = reader.GetString(0);
            available = reader.GetInt64(1);
        }
        using var destination = await target.OpenConnectionAsync(cancellation);
        var cursor = await CursorAsync(destination, null, databaseId, cancellation);
        if (cursor > available)
            throw new InvalidDataException("The source journal was rolled back. Use a new capture journal.");
        if (cursor == available)
        {
            read.Commit();
            await AcknowledgeAsync(path, target, cursor, cancellation);
            return (cursor, 0, false);
        }

        // Never split a committed revision; a batch stays bounded without skipping updated rows.
        using var boundary = source.CreateCommand();
        boundary.Transaction = read;
        boundary.CommandText = """
            SELECT DISTINCT change_revision FROM (
                SELECT change_revision FROM connections WHERE change_revision>@after
                UNION ALL SELECT change_revision FROM certificates WHERE change_revision>@after
                UNION ALL SELECT change_revision FROM connection_certificates WHERE change_revision>@after
                UNION ALL SELECT change_revision FROM endpoint_events WHERE change_revision>@after
                UNION ALL SELECT change_revision FROM capture_sessions WHERE change_revision>@after)
            ORDER BY change_revision LIMIT 4
            """;
        boundary.Parameters.AddWithValue("@after", cursor);
        long upper = available;
        using (var reader = await boundary.ExecuteReaderAsync(cancellation))
        {
            var revisions = new List<long>(4);
            while (reader.Read())
                revisions.Add(reader.GetInt64(0));
            if (revisions.Count == 4)
                upper = revisions[^1];
        }
        const string changed = "change_revision>@after AND change_revision<=@upper";
        var connectionScope = $"({changed}) OR (run_id,flow_id) IN " +
            $"(SELECT run_id,flow_id FROM connection_certificates WHERE {changed})";
        var linkScope = $"(run_id,flow_id) IN (SELECT run_id,flow_id FROM connections WHERE {connectionScope})";
        // A coalesced parent may have a newer revision than its links; publish their complete dependency closure.
        var connections = ReadTable(source, read, "connections", ConnectionColumns,
            connectionScope, cursor, upper, cancellation);
        var sessions = ReadTable(source, read, "capture_sessions", SessionColumns,
            "(change_revision>@after AND change_revision<=@upper) OR id IN " +
            $"(SELECT run_id FROM connections WHERE {connectionScope} " +
            "UNION SELECT run_id FROM endpoint_events WHERE change_revision>@after AND change_revision<=@upper)",
            cursor, upper, cancellation);
        var certificates = ReadTable(source, read, "certificates", CertificateColumns,
            $"({changed}) OR sha256 IN (SELECT sha256 FROM connection_certificates WHERE {linkScope})",
            cursor, upper, cancellation);
        var links = ReadTable(source, read, "connection_certificates", CertificateLinkColumns,
            linkScope, cursor, upper, cancellation);
        var events = ReadTable(source, read, "endpoint_events", EventColumns,
            "change_revision>@after AND change_revision<=@upper", cursor, upper, cancellation);
        read.Commit();

        // One row lock establishes commit order for every source and the viewer's durable cursor.
        using var write = await destination.BeginTransactionAsync(cancellation);
        using var command = destination.CreateCommand();
        command.Transaction = write;
        command.CommandText = "UPDATE cipherazzi.metadata SET revision=revision+1 WHERE id=1";
        await command.ExecuteNonQueryAsync(cancellation);
        if (await CursorAsync(destination, write, databaseId, cancellation) != cursor)
        {
            await write.RollbackAsync(cancellation);
            return (cursor, 0, true);
        }
        command.CommandText = "SELECT revision FROM cipherazzi.metadata WHERE id=1";
        var revision = Convert.ToInt64(await command.ExecuteScalarAsync(cancellation));
        foreach (var table in new[] { sessions, connections, certificates, events, links })
            foreach (DataRow row in table.Rows)
                row["change_revision"] = revision;
        await WriteTableAsync(destination, write, target.Provider, sessions, SessionColumns, ["id"], cancellation);
        await WriteTableAsync(destination, write, target.Provider, connections, ConnectionColumns,
            ["run_id", "flow_id"], cancellation);
        await WriteTableAsync(destination, write, target.Provider, certificates, CertificateColumns,
            ["sha256"], cancellation);
        await WriteTableAsync(destination, write, target.Provider, events, EventColumns, ["id"], cancellation);
        await WriteTableAsync(destination, write, target.Provider, links, CertificateLinkColumns,
            ["run_id", "flow_id", "role", "chain_index"], cancellation);
        command.CommandText = target.Provider == DatabaseProvider.SqlServer ? """
            UPDATE cipherazzi.replication_sources SET revision=@revision WHERE source_id=@source;
            IF @@ROWCOUNT=0 INSERT INTO cipherazzi.replication_sources VALUES(@source,@revision);
            """ : """
            INSERT INTO cipherazzi.replication_sources VALUES(@source,@revision)
            ON CONFLICT(source_id) DO UPDATE SET revision=excluded.revision;
            """;
        DatabaseSource.AddParameter(command, "@source", databaseId);
        DatabaseSource.AddParameter(command, "@revision", upper);
        await command.ExecuteNonQueryAsync(cancellation);
        await write.CommitAsync(cancellation);
        // A lost acknowledgement retains extra local data; it can never authorize deletion before commit.
        await AcknowledgeAsync(path, target, upper, cancellation);
        return (upper, connections.Rows.Count, upper < available);
    }

    private static DataTable ReadTable(SqliteConnection source, SqliteTransaction transaction, string name,
        string[] columns, string condition, long after, long upper, CancellationToken cancellation)
    {
        var table = new DataTable(name);
        foreach (var column in columns)
            table.Columns.Add(column, column == "der" ? typeof(byte[]) :
                TextColumns.Contains(column) ? typeof(string) : typeof(long));
        using var command = source.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT {string.Join(',', columns)} FROM {name} WHERE {condition}";
        command.Parameters.AddWithValue("@after", after);
        command.Parameters.AddWithValue("@upper", upper);
        using var cancel = cancellation.Register(command.Cancel);
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            cancellation.ThrowIfCancellationRequested();
            var values = new object[columns.Length];
            reader.GetValues(values);
            table.Rows.Add(values);
        }
        return table;
    }

    private static async Task WriteTableAsync(DbConnection connection, DbTransaction transaction,
        DatabaseProvider provider, DataTable data, string[] columns, string[] keys, CancellationToken cancellation)
    {
        if (data.Rows.Count == 0)
            return;
        var names = string.Join(',', columns);
        var sqlServer = provider == DatabaseProvider.SqlServer;
        var stage = sqlServer ? "#" + data.TableName : "stage_" + data.TableName;
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sqlServer ?
            $"SELECT TOP (0) {names} INTO {stage} FROM cipherazzi.{data.TableName};" :
            $"CREATE TEMP TABLE {stage} ON COMMIT DROP AS SELECT {names} FROM cipherazzi.{data.TableName} WITH NO DATA;";
        await command.ExecuteNonQueryAsync(cancellation);
        if (sqlServer)
        {
            using var bulk = new SqlBulkCopy((SqlConnection)connection, SqlBulkCopyOptions.Default,
                (SqlTransaction)transaction) { DestinationTableName = stage, BulkCopyTimeout = 30 };
            foreach (var column in columns)
                bulk.ColumnMappings.Add(column, column);
            await bulk.WriteToServerAsync(data, cancellation);
        }
        else
        {
            await using var bulk = await ((NpgsqlConnection)connection).BeginBinaryImportAsync(
                $"COPY {stage}({names}) FROM STDIN (FORMAT BINARY)", cancellation);
            foreach (DataRow row in data.Rows)
            {
                await bulk.StartRowAsync(cancellation);
                foreach (var column in columns)
                {
                    if (row.IsNull(column))
                        await bulk.WriteNullAsync(cancellation);
                    else if (TextColumns.Contains(column))
                        await bulk.WriteAsync((string)row[column], NpgsqlDbType.Text, cancellation);
                    else if (column == "der")
                        await bulk.WriteAsync((byte[])row[column], NpgsqlDbType.Bytea, cancellation);
                    else
                        await bulk.WriteAsync((long)row[column], NpgsqlDbType.Bigint, cancellation);
                }
            }
            await bulk.CompleteAsync(cancellation);
        }
        var updates = columns.Except(keys);
        if (sqlServer)
        {
            var join = string.Join(" AND ", keys.Select(key => $"t.{key}=s.{key}"));
            command.CommandText = $"UPDATE t SET {string.Join(',', updates.Select(c => $"{c}=s.{c}"))} " +
                $"FROM cipherazzi.{data.TableName} t JOIN {stage} s ON {join};" +
                $"INSERT INTO cipherazzi.{data.TableName}({names}) SELECT " +
                $"{string.Join(',', columns.Select(c => "s." + c))} FROM {stage} s " +
                $"WHERE NOT EXISTS(SELECT 1 FROM cipherazzi.{data.TableName} t WHERE {join});" +
                $"DROP TABLE {stage};";
        }
        else
        {
            command.CommandText = $"INSERT INTO cipherazzi.{data.TableName}({names}) SELECT {names} FROM {stage} " +
                $"ON CONFLICT({string.Join(',', keys)}) DO UPDATE SET " +
                string.Join(',', updates.Select(c => $"{c}=excluded.{c}")) + ";";
        }
        await command.ExecuteNonQueryAsync(cancellation);
    }
}
