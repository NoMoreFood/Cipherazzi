using System.Data.Common;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

SQLitePCL.Batteries_V2.Init();
if (args.FirstOrDefault() == "--investigation-remote")
{
    await Investigation.RunRemoteAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--investigation")
{
    Investigation.Run(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--protocol-policies")
{
    ProtocolPolicies.Run(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--endpoint-evidence")
{
    await EndpointFeatures.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--browser-endpoint-evidence")
{
    EndpointFeatures.RunBrowser(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--retention")
{
    await RetentionFeatures.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--data-stress")
{
    await AdversarialData.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--migration-remote")
{
    await MigrationRemote.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--migration")
{
    MigrationFeatures.Run(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--sqlite-stress")
{
    await SqliteStress.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--stress")
{
    await StressConnectivity.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--advanced")
{
    await AdvancedConnectivity.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--pqc")
{
    await PqcConnectivity.RunAsync(args[1..]);
    return;
}
if (args.FirstOrDefault() == "--connectivity")
{
    await PackagedConnectivity.RunAsync(args[1..]);
    return;
}
var directory = Path.GetFullPath(args[1]);
Directory.CreateDirectory(directory);
var path = Path.Combine(directory, "replication.db");
var prefix = Guid.NewGuid().ToString("N");
using (var source = (SqliteConnection)DatabaseSource.Sqlite(args[0]).CreateConnection())
using (var destination = new SqliteConnection($"Data Source={path}"))
{
    source.Open();
    destination.Open();
    source.BackupDatabase(destination);
    using var command = destination.CreateCommand();
    command.CommandText = """
        PRAGMA foreign_keys=OFF;
        BEGIN IMMEDIATE;
        UPDATE metadata SET database_id=lower(hex(randomblob(16)));
        UPDATE capture_sessions SET id=@prefix||id;
        UPDATE connections SET run_id=@prefix||run_id;
        UPDATE connection_certificates SET run_id=@prefix||run_id;
        UPDATE endpoint_events SET run_id=@prefix||run_id;
        COMMIT;
        """;
    command.Parameters.AddWithValue("@prefix", prefix);
    command.ExecuteNonQuery();
}
var local = DatabaseSource.Sqlite(path);
var targets = new[]
{
    DatabaseSource.FromEnvironment("sqlserver", "CIPHERAZZI_SQLSERVER"),
    DatabaseSource.FromEnvironment("postgresql", "CIPHERAZZI_POSTGRESQL")
};
var results = new List<object>();
using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));

// New databases isolate schema and binary certificate checks from earlier lab captures.
if (args.Contains("--fresh"))
{
    for (var index = 0; index < targets.Length; ++index)
    {
        var target = targets[index];
        var name = "CipherazziCrypto_" + Guid.NewGuid().ToString("N")[..10];
        var builder = target.Provider == DatabaseProvider.SqlServer ?
            (DbConnectionStringBuilder)new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(target.ConnectionString) :
            new Npgsql.NpgsqlConnectionStringBuilder(target.ConnectionString);
        builder[target.Provider == DatabaseProvider.SqlServer ? "Initial Catalog" : "Database"] =
            target.Provider == DatabaseProvider.SqlServer ? "master" : "postgres";
        using var server = new DatabaseSource(target.Provider, builder.ConnectionString).CreateConnection();
        server.Open();
        using var command = server.CreateCommand();
        command.CommandText = target.Provider == DatabaseProvider.SqlServer ?
            $"CREATE DATABASE [{name}]" : $"CREATE DATABASE \"{name}\"";
        command.ExecuteNonQuery();
        builder[target.Provider == DatabaseProvider.SqlServer ? "Initial Catalog" : "Database"] = name;
        targets[index] = new(target.Provider, builder.ConnectionString);
        ConnectionCredentials.Save(Path.Combine(directory, target.Provider + ".credential"), targets[index]);
    }
}

if (args.Length > 3)
{
    using var writer = new SqliteConnection($"Data Source={path}");
    writer.Open();
    using var command = writer.CreateCommand();
    command.CommandText = "ATTACH DATABASE @crypto AS crypto";
    command.Parameters.AddWithValue("@crypto", args[3]);
    command.ExecuteNonQuery();
    command.CommandText = """
        BEGIN IMMEDIATE;
        UPDATE metadata SET revision=revision+1;
        INSERT INTO certificates SELECT sha256,metadata_json,der,(SELECT revision FROM metadata) FROM crypto.certificates;
        INSERT INTO connection_certificates SELECT run_id,flow_id,'server',0,
            (SELECT sha256 FROM certificates LIMIT 1),(SELECT revision FROM metadata)
            FROM connections ORDER BY id LIMIT 1;
        INSERT INTO endpoint_events SELECT 'lab-endpoint',id,started_us,'Java Flight Recorder','jdk.TLSHandshake',
            'Endpoint reported TLS handshake',1234,'telemetry.test',443,'TLSv1.3','TLS_AES_256_GCM_SHA384','fixture',
            '{"source":"replication test"}',(SELECT revision FROM metadata) FROM capture_sessions LIMIT 1;
        UPDATE certificates SET change_revision=1;
        UPDATE connection_certificates SET change_revision=1;
        UPDATE connections SET change_revision=(SELECT revision FROM metadata)
            WHERE id=(SELECT min(id) FROM connections);
        COMMIT;
        """;
    command.ExecuteNonQuery();
}

async Task CatchUp(DatabaseSource target)
{
    while ((await Replication.SyncAsync(path, target, deadline.Token)).More) {}
}

string Fingerprint(DatabaseSource source)
{
    using var connection = source.CreateConnection();
    connection.Open();
    using var command = connection.CreateCommand();
    command.CommandText = $"SELECT * FROM {source.Prefix}connections WHERE run_id LIKE @prefix " +
        "ORDER BY run_id,flow_id";
    DatabaseSource.AddParameter(command, "@prefix", prefix + "%");
    using var reader = command.ExecuteReader();
    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    var columns = Enumerable.Range(0, reader.FieldCount)
        .Where(index => reader.GetName(index) is not "id" and not "change_revision")
        .OrderBy(index => reader.GetName(index)).ToArray();
    while (reader.Read())
        hash.AppendData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(columns.Select(index =>
            reader.IsDBNull(index) ? null : Convert.ToString(reader[index], System.Globalization.CultureInfo.InvariantCulture)))));
    return Convert.ToHexString(hash.GetHashAndReset());
}

void Assert(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

foreach (var target in targets)
{
    await Replication.InitializeAsync(target, deadline.Token);
    var watch = Stopwatch.StartNew();
    await CatchUp(target);
    var seconds = watch.Elapsed.TotalSeconds;
    Assert(Fingerprint(local) == Fingerprint(target), "The initial copy changed observation data.");
    var empty = await Replication.SyncAsync(path, target, deadline.Token);
    Assert(empty.Connections == 0 && !empty.More, "An idle reconnect duplicated data.");
    var page = Database.Read(target, new Query("", "TLS 1.3", false, PageCursor.Newest), deadline.Token);
    Assert(page.Rows.Count == 250 && page.HasMore, "Server-side paging failed.");
    Assert(page.Rows.All(row => row.Value("Computer") == Environment.MachineName),
        "The collector computer did not reach the viewer.");
    var last = page.Rows[^1];
    var older = Database.Read(target, new Query("", "TLS 1.3", false, new PageCursor(last.FirstUs, last.Id)),
        deadline.Token);
    Assert(!page.Rows.Select(row => row.Id).Intersect(older.Rows.Select(row => row.Id)).Any(), "Pages overlap.");
    foreach (var dimension in Insights.Dimensions.Keys)
    {
        var summary = Insights.ReadAnalytics(target, new Query("", "TLS 1.3", false, PageCursor.Newest),
            0, dimension, 20, deadline.Token);
        Assert(summary.Total == 20000 && summary.Timeline.Sum(point => point.Count) == 20000,
            "Analytics did not query the complete scope.");
    }
    if (args.Length > 3)
    {
        using var original = local.CreateConnection();
        using var copy = target.CreateConnection();
        original.Open();
        copy.Open();
        using var a = original.CreateCommand();
        using var b = copy.CreateCommand();
        a.CommandText = "SELECT der FROM certificates";
        b.CommandText = "SELECT der FROM cipherazzi.certificates";
        Assert(((byte[])a.ExecuteScalar()!).SequenceEqual((byte[])b.ExecuteScalar()!),
            "Replication changed the original DER certificate bytes.");
        b.CommandText = "SELECT count(*) FROM cipherazzi.connection_certificates";
        Assert(Convert.ToInt64(b.ExecuteScalar()) == 1, "Certificate links were not replicated.");
        Assert(Insights.ReadEvents(target, "telemetry", long.MaxValue, "\uffff", 0, deadline.Token).Count == 1,
            "Endpoint telemetry was not replicated.");
    }
    results.Add(new { provider = target.Provider.ToString(), initial_seconds = seconds, rows = 20000 });
}

// Update existing rows after initial publication, including nulls, Unicode, and LIKE metacharacters.
using (var writer = new SqliteConnection($"Data Source={path}"))
{
    writer.Open();
    using var command = writer.CreateCommand();
    command.CommandText = """
        BEGIN IMMEDIATE;
        UPDATE metadata SET revision=revision+1;
        UPDATE connections SET source_process='java-Δ%_[.exe',source_pid=2147483000,source_path='C:\Δ\java.exe',
            source_account='sam-Δ%_[',source_account_domain='LAB',source_account_sid='S-1-5-21-1-2-3-1001',
            destination_account='service-Ω',destination_account_domain='SERVER',
            destination_account_sid='S-1-5-21-4-5-6-1002',
            detail='Late attribution',change_revision=(SELECT revision FROM metadata)
            WHERE id IN(SELECT id FROM connections ORDER BY id LIMIT 10);
        COMMIT;
        """;
    command.ExecuteNonQuery();
}
foreach (var target in targets)
{
    // Two replicas racing the same cursor must not regress rows or create duplicate observations.
    await Task.WhenAll(CatchUp(target), CatchUp(target));
    Assert(Fingerprint(local) == Fingerprint(target), "Late updates or concurrent replicas corrupted data.");
    var matching = Database.Read(target, new Query("Δ%_[", "", false, PageCursor.Newest), deadline.Token);
    Assert(matching.Rows.Count == 10, "Literal wildcard or Unicode search failed.");
    var accounts = Database.Read(target, new Query("LAB\\sam-Δ%_[", "", false, PageCursor.Newest), deadline.Token);
    Assert(accounts.Rows.Count == 10 && accounts.Rows.All(row => row.Value("ClientOwner") == "LAB\\sam-Δ%_[" &&
        row.Value("ServerOwner") == "SERVER\\service-Ω" && row.Value("ClientSid") == "S-1-5-21-1-2-3-1001" &&
        row.Value("ServerSid") == "S-1-5-21-4-5-6-1002"), "Process accounts did not reach the viewer or search.");
    var owners = Insights.ReadAnalytics(target, new Query("LAB\\sam-Δ%_[", "", false, PageCursor.Newest),
        0, "Client owner", 20, deadline.Token);
    Assert(owners.Total == 10 && owners.Breakdown.Single().Name == "LAB\\sam-Δ%_[",
        "Account analytics did not preserve the qualified account name.");
    var revision = matching.Revision;
    Assert(Database.ReadIfChanged(target, new Query("", "", false, PageCursor.Newest), deadline.Token,
        revision) is null, "An unchanged revision was reread.");
}
File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(new
{
    results, exact_data_roundtrip = true, concurrent_resume = true, late_updates = true, literal_search = true,
    paging = true, source = path, analytics = true, certificate_der_and_links = args.Length > 3,
    endpoint_events = args.Length > 3, process_accounts = true, collector_computer = true
}, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine("SQL Server and PostgreSQL: exact data, late updates, concurrent resume, search, and paging passed.");
