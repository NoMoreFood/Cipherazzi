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

    private static async Task AcknowledgeAsync(string path, DatabaseSource target, long? revision,
        CancellationToken cancellation, string? databaseId = null, long minimumRevision = 0)
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

        // Registration protects history before connecting; synchronization reconciles the destination's actual
        // cursor, including a restored database. Unchanged checkpoints leave an idle journal unwritten.
        using (var recorded = connection.CreateCommand())
        {
            recorded.CommandText =
                "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='replication_consumers'";
            if (Convert.ToInt64(await recorded.ExecuteScalarAsync(cancellation)) != 0)
            {
                recorded.CommandText =
                    "SELECT acknowledged_revision FROM replication_consumers WHERE target_id=@target " +
                    "AND (@source IS NULL OR EXISTS(SELECT 1 FROM metadata WHERE id=1 " +
                        "AND database_id=@source AND revision>=@minimum))";
                recorded.Parameters.AddWithValue("@target", id);
                recorded.Parameters.AddWithValue("@source", (object?)databaseId ?? DBNull.Value);
                recorded.Parameters.AddWithValue("@minimum", minimumRevision);
                if (await recorded.ExecuteScalarAsync(cancellation) is long acknowledged &&
                    (revision is null || acknowledged == revision))
                    return;
            }
        }
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var changed = false;
        if (databaseId is not null)
        {
            command.CommandText = "SELECT database_id=@source AND revision>=@minimum FROM metadata WHERE id=1";
            command.Parameters.AddWithValue("@source", databaseId);
            command.Parameters.AddWithValue("@minimum", minimumRevision);
            changed = Convert.ToInt64(await command.ExecuteScalarAsync(cancellation)) != 1;
            command.Parameters.Clear();
        }

        // A restore can replace or roll back the source; protect its pending history before failing.
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS replication_consumers (
                target_id TEXT PRIMARY KEY, acknowledged_revision INTEGER NOT NULL CHECK(acknowledged_revision>=0),
                updated_us INTEGER NOT NULL) STRICT;
            INSERT INTO replication_consumers VALUES(@target,@revision,@time)
            ON CONFLICT(target_id) DO UPDATE SET
                acknowledged_revision=excluded.acknowledged_revision,
                updated_us=excluded.updated_us;
            """;
        command.Parameters.AddWithValue("@target", id);
        command.Parameters.AddWithValue("@revision", changed ? 0L : revision ?? 0);
        command.Parameters.AddWithValue("@time", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000);
        await command.ExecuteNonQueryAsync(cancellation);
        transaction.Commit();
        if (changed)
            throw new InvalidDataException("The source journal changed during replication. Restart the relay.");
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
    private static readonly string[] EndpointCertificateColumns = ["event_id", "sha256"];
    private static readonly string[] EventColumns = (
        "id,run_id,timestamp_us,provider,kind,result,pid,peer,port,protocol,cipher,certificate_id," +
        "detail_json,change_revision").Split(',');
    private static readonly HashSet<string> TextColumns = [
        "id", "run_id", "event_id", "source", "process_status", "status", "source_address", "destination_address",
        "tls_name",
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
        var sqlServer = target.Provider == DatabaseProvider.SqlServer;
        if (sqlServer)
        {
            // Versioned evidence reads keep reports and readiness independent of ingestion row locks.
            using var settings = connection.CreateCommand();
            settings.CommandText = "IF EXISTS(SELECT 1 FROM sys.databases WHERE database_id=DB_ID() " +
                "AND snapshot_isolation_state<>1) ALTER DATABASE CURRENT SET ALLOW_SNAPSHOT_ISOLATION ON";
            await settings.ExecuteNonQueryAsync(cancellation);
        }
        using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellation);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sqlServer ?
            "IF SCHEMA_ID('cipherazzi') IS NULL EXEC('CREATE SCHEMA cipherazzi');" :
            "CREATE SCHEMA IF NOT EXISTS cipherazzi;";
        await command.ExecuteNonQueryAsync(cancellation);
        string TextType(string name) => sqlServer ? name switch
        {
            "id" or "run_id" or "event_id" or "sha256" => "nvarchar(128)",
            "role" => "nvarchar(16)",
            "sni" => "nvarchar(253)",
            _ => "nvarchar(max)"
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
                "revision bigint NOT NULL,observation_revision bigint NOT NULL DEFAULT 0") +
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
            Create("endpoint_certificates", Definition(EndpointCertificateColumns) +
                ",PRIMARY KEY(event_id,sha256),FOREIGN KEY(event_id) REFERENCES cipherazzi.endpoint_events(id)," +
                "FOREIGN KEY(sha256) REFERENCES cipherazzi.certificates(sha256)") +
            (sqlServer ?
                "IF NOT EXISTS(SELECT 1 FROM cipherazzi.metadata) " +
                "INSERT INTO cipherazzi.metadata(id,schema_version,revision) VALUES(1,4,0);" +
                "IF NOT EXISTS(SELECT 1 FROM sys.indexes WHERE name='connections_time' " +
                "AND object_id=OBJECT_ID('cipherazzi.connections')) " +
                "CREATE INDEX connections_time ON cipherazzi.connections(first_us DESC,id DESC);" +
                "IF NOT EXISTS(SELECT 1 FROM sys.indexes WHERE name='connections_changes' " +
                "AND object_id=OBJECT_ID('cipherazzi.connections')) " +
                "CREATE INDEX connections_changes ON cipherazzi.connections(change_revision);" +
                "IF NOT EXISTS(SELECT 1 FROM sys.indexes WHERE name='endpoint_certificates_hash' " +
                "AND object_id=OBJECT_ID('cipherazzi.endpoint_certificates')) " +
                "CREATE INDEX endpoint_certificates_hash ON cipherazzi.endpoint_certificates(sha256);" :
                "INSERT INTO cipherazzi.metadata(id,schema_version,revision) VALUES(1,4,0) ON CONFLICT DO NOTHING;" +
                "CREATE INDEX IF NOT EXISTS connections_time ON cipherazzi.connections(first_us DESC,id DESC);" +
                "CREATE INDEX IF NOT EXISTS connections_changes ON cipherazzi.connections(change_revision);" +
                "CREATE INDEX IF NOT EXISTS endpoint_certificates_hash ON cipherazzi.endpoint_certificates(sha256);");
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
        await AcknowledgeAsync(path, target, null, cancellation);
        using var source = (SqliteConnection)await DatabaseSource.Sqlite(path).OpenConnectionAsync(cancellation);
        DatabaseSource.Sqlite(path).Validate(source, cancellation);
        using var identity = source.CreateCommand();
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
        {
            await RegisterAsync(path, target, cancellation);
            throw new InvalidDataException("The source journal was rolled back. Use a new capture journal.");
        }
        await AcknowledgeAsync(path, target, cursor, cancellation, databaseId, available);

        // Stage snapshots in file-backed temporary storage before network writes, keeping managed memory bounded.
        using (var temporary = source.CreateCommand())
        {
            temporary.CommandText = "PRAGMA temp_store=FILE; PRAGMA temp.cache_size=-4096";
            await temporary.ExecuteNonQueryAsync(cancellation);
        }

        // Reconcile retention before holding a source snapshot; rollback journals cannot commit another writer
        // while that snapshot is open. Read the upload boundary from the snapshot after reconciliation.
        using var read = source.BeginTransaction(deferred: true);
        identity.Transaction = read;
        identity.CommandText = "SELECT revision FROM metadata WHERE id=1 AND database_id=@source";
        identity.Parameters.AddWithValue("@source", databaseId);
        if (await identity.ExecuteScalarAsync(cancellation) is not long currentRevision || currentRevision < cursor)
        {
            read.Commit();
            await RegisterAsync(path, target, cancellation);
            throw new InvalidDataException("The source journal changed during replication. Restart the relay.");
        }
        available = currentRevision;
        if (cursor == available)
        {
            read.Commit();
            return (cursor, 0, false);
        }

        // Keep revision boundaries intact and group a few commits per snapshot.
        using var boundary = source.CreateCommand();
        boundary.Transaction = read;
        boundary.CommandText = string.Join(" UNION ", new[]
            { "connections", "certificates", "connection_certificates", "endpoint_events", "capture_sessions" }
            .Select(table => $"SELECT change_revision FROM (SELECT DISTINCT change_revision FROM {table} " +
                "WHERE change_revision>@after ORDER BY change_revision LIMIT 4)")) +
            " ORDER BY change_revision LIMIT 4";
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
        var endpointLinkScope = $"event_id IN (SELECT id FROM endpoint_events WHERE {changed})";

        // A coalesced parent may have a newer revision than its links; publish their complete dependency closure.
        var connections = StageTable(source, read, "connections", ConnectionColumns,
            connectionScope, cursor, upper, cancellation);
        var sessions = StageTable(source, read, "capture_sessions", SessionColumns,
            "(change_revision>@after AND change_revision<=@upper) OR id IN " +
            $"(SELECT run_id FROM connections WHERE {connectionScope} " +
            "UNION SELECT run_id FROM endpoint_events WHERE change_revision>@after AND change_revision<=@upper)",
            cursor, upper, cancellation);
        var certificates = StageTable(source, read, "certificates", CertificateColumns,
            $"({changed}) OR sha256 IN (SELECT sha256 FROM connection_certificates WHERE {linkScope}) OR " +
                $"sha256 IN (SELECT sha256 FROM endpoint_certificates WHERE {endpointLinkScope})",
            cursor, upper, cancellation);
        var links = StageTable(source, read, "connection_certificates", CertificateLinkColumns,
            linkScope, cursor, upper, cancellation);
        var events = StageTable(source, read, "endpoint_events", EventColumns,
            "change_revision>@after AND change_revision<=@upper", cursor, upper, cancellation);
        var endpointLinks = StageTable(source, read, "endpoint_certificates", EndpointCertificateColumns,
            endpointLinkScope, cursor, upper, cancellation);
        read.Commit();

        // One row lock establishes commit order for every source and the viewer's durable cursor.
        using var write = await destination.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellation);
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
        await WriteTableAsync(source, destination, write, target.Provider, "capture_sessions", sessions,
            SessionColumns, ["id"], revision, cancellation);
        await WriteTableAsync(source, destination, write, target.Provider, "connections", connections,
            ConnectionColumns, ["run_id", "flow_id"], revision, cancellation);
        await WriteTableAsync(source, destination, write, target.Provider, "certificates", certificates,
            CertificateColumns, ["sha256"], revision, cancellation);
        await WriteTableAsync(source, destination, write, target.Provider, "endpoint_events", events,
            EventColumns, ["id"], revision, cancellation);
        await WriteTableAsync(source, destination, write, target.Provider, "connection_certificates", links,
            CertificateLinkColumns, ["run_id", "flow_id", "role", "chain_index"], revision, cancellation);
        await WriteTableAsync(source, destination, write, target.Provider, "endpoint_certificates", endpointLinks,
            EndpointCertificateColumns, EndpointCertificateColumns, revision, cancellation);
        if (connections > 0 || certificates > 0 || events > 0 || links > 0 || endpointLinks > 0)
        {
            command.CommandText = "UPDATE cipherazzi.metadata SET observation_revision=revision WHERE id=1";
            await command.ExecuteNonQueryAsync(cancellation);
        }
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
        await AcknowledgeAsync(path, target, upper, cancellation, databaseId, available);
        return (upper, connections, upper < available);
    }

    private static int StageTable(SqliteConnection source, SqliteTransaction transaction, string name,
        string[] columns, string condition, long after, long upper, CancellationToken cancellation)
    {
        // Copy one committed snapshot without decoding and retaining every row in managed memory.
        var names = string.Join(',', columns);
        using var command = source.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"CREATE TEMP TABLE relay_{name} AS SELECT {names} FROM main.{name} WHERE 0";
        using var cancel = cancellation.Register(command.Cancel);
        command.ExecuteNonQuery();
        command.CommandText = $"INSERT INTO temp.relay_{name} SELECT {names} FROM main.{name} WHERE {condition}";
        command.Parameters.AddWithValue("@after", after);
        command.Parameters.AddWithValue("@upper", upper);
        return command.ExecuteNonQuery();
    }

    private static async Task WriteTableAsync(SqliteConnection source, DbConnection connection,
        DbTransaction transaction, DatabaseProvider provider, string name, int count, string[] columns, string[] keys,
        long revision, CancellationToken cancellation)
    {
        if (count == 0)
            return;
        var names = string.Join(',', columns);
        var sqlServer = provider == DatabaseProvider.SqlServer;
        var stage = sqlServer ? "#" + name : "stage_" + name;
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sqlServer ?
            $"SELECT TOP (0) {names} INTO {stage} FROM cipherazzi.{name};" :
            $"CREATE TEMP TABLE {stage} ON COMMIT DROP AS SELECT {names} " +
            $"FROM cipherazzi.{name} WITH NO DATA;";
        await command.ExecuteNonQueryAsync(cancellation);

        // Stream the captured values with the destination revision after releasing the journal's read transaction.
        using var captured = source.CreateCommand();
        captured.CommandText = "SELECT " + string.Join(',', columns.Select(column =>
            column == "change_revision" ? "@revision AS change_revision" : column)) +
            $" FROM temp.relay_{name} WHERE rowid>@after AND rowid<=@through";
        captured.Parameters.AddWithValue("@revision", revision);
        captured.Parameters.AddWithValue("@after", 0L);
        captured.Parameters.AddWithValue("@through", 0L);
        using var cancel = cancellation.Register(captured.Cancel);
        using var sqlBulk = sqlServer ? new SqlBulkCopy((SqlConnection)connection, SqlBulkCopyOptions.Default,
            (SqlTransaction)transaction) { DestinationTableName = stage, BulkCopyTimeout = 30 } : null;
        if (sqlBulk is not null)
            foreach (var column in columns)
                sqlBulk.ColumnMappings.Add(column, column);
        var updates = columns.Except(keys).ToArray();
        string publish;
        if (sqlServer)
        {
            // Wide text estimates must not reserve the server's workspace for a bounded relay batch.
            var join = string.Join(" AND ", keys.Select(key => $"t.{key}=s.{key}"));
            publish = (updates.Length == 0 ? "" :
                $"UPDATE t SET {string.Join(',', updates.Select(c => $"{c}=s.{c}"))} " +
                $"FROM cipherazzi.{name} t JOIN {stage} s ON {join} OPTION(MAX_GRANT_PERCENT=1);") +
                $"INSERT INTO cipherazzi.{name}({names}) SELECT " +
                $"{string.Join(',', columns.Select(c => "s." + c))} FROM {stage} s " +
                $"WHERE NOT EXISTS(SELECT 1 FROM cipherazzi.{name} t WHERE {join}) OPTION(MAX_GRANT_PERCENT=1);";
        }
        else
            publish = $"INSERT INTO cipherazzi.{name}({names}) SELECT {names} FROM {stage} " +
                $"ON CONFLICT({string.Join(',', keys)}) DO " + (updates.Length == 0 ? "NOTHING" :
                "UPDATE SET " + string.Join(',', updates.Select(c => $"{c}=excluded.{c}"))) + ";";

        // Bound each server operation while the enclosing transaction publishes the complete source revision.
        for (long after = 0; after < count; after += 1024)
        {
            cancellation.ThrowIfCancellationRequested();
            captured.Parameters["@after"].Value = after;
            captured.Parameters["@through"].Value = after + 1024;
            using var reader = captured.ExecuteReader(CommandBehavior.SequentialAccess);
            if (sqlBulk is not null)
                await sqlBulk.WriteToServerAsync(reader, cancellation);
            else
            {
                await using var bulk = await ((NpgsqlConnection)connection).BeginBinaryImportAsync(
                    $"COPY {stage}({names}) FROM STDIN (FORMAT BINARY)", cancellation);
                while (await reader.ReadAsync(cancellation))
                {
                    await bulk.StartRowAsync(cancellation);
                    for (var index = 0; index < columns.Length; ++index)
                    {
                        var column = columns[index];
                        if (reader.IsDBNull(index))
                            await bulk.WriteNullAsync(cancellation);
                        else if (TextColumns.Contains(column))
                            await bulk.WriteAsync(reader.GetString(index), NpgsqlDbType.Text, cancellation);
                        else if (column == "der")
                            await bulk.WriteAsync((byte[])reader.GetValue(index), NpgsqlDbType.Bytea, cancellation);
                        else
                            await bulk.WriteAsync(reader.GetInt64(index), NpgsqlDbType.Bigint, cancellation);
                    }
                }
                await bulk.CompleteAsync(cancellation);
            }
            command.CommandText = publish + $"TRUNCATE TABLE {stage}";
            await command.ExecuteNonQueryAsync(cancellation);
        }
        command.CommandText = $"DROP TABLE {stage}";
        await command.ExecuteNonQueryAsync(cancellation);
    }
}
