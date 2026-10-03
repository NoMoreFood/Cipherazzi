using System.Data.Common;

namespace Cipherazzi.Data;

public sealed record ConnectionRow(
    long Id, long FirstUs, string Time, string Source, string Destination, string Tls,
    string Cipher, string Sni, string Process, string State)
{
    public Dictionary<string, string> Values { get; init; } = [];
    private Lazy<List<ObservationProperty>> properties = new(() => []);
    public List<ObservationProperty> Properties
    {
        get => properties.Value;
        init => properties = new(() => value);
    }
    public Func<List<ObservationProperty>> PropertyFactory { init => properties = new(value); }
    public string[] Certificates { get; init; } = [];
    public string Value(string name) => Values.GetValueOrDefault(name, "");
}

public sealed record PageCursor(long Time, long Id)
{
    public static PageCursor Newest { get; } = new(long.MaxValue, long.MaxValue);
}

public sealed record Snapshot(List<ConnectionRow> Rows, bool HasMore, string Health, string Diagnostics,
    (string Identity, long Revision) Stamp);

public sealed record CaptureHealth(string Health, string Diagnostics);

public static class Database
{
    public const int PageSize = 250;

    public static (string Identity, long Revision) ReadStamp(DatabaseSource source, CancellationToken cancellation)
    {
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var command = connection.CreateCommand();
        command.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 2 : 5;
        command.CommandText = $"SELECT * FROM {source.Prefix}metadata WHERE id=1";
        using var registration = cancellation.Register(command.Cancel);
        using var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
        if (!reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            throw new InvalidDataException("Journal revision is unavailable.");
        return (source.Provider == DatabaseProvider.Sqlite ? (string)reader["database_id"] : "server",
            ObservationRevision(reader));
    }

    internal static long ObservationRevision(DbDataReader reader)
    {
        for (var index = 0; index < reader.FieldCount; ++index)
            if (reader.GetName(index) == "observation_revision")
                return Convert.ToInt64(reader[index]);
        return Convert.ToInt64(reader["revision"]);
    }

    public static Snapshot Read(string path, Query query, CancellationToken cancellation,
        FindingPolicy? policy = null) =>
        Read(DatabaseSource.Sqlite(path), query, cancellation, policy);

    public static Snapshot Read(DatabaseSource source, Query query, CancellationToken cancellation,
        FindingPolicy? policy = null)
        => ReadIfChanged(source, query, cancellation, null, policy)!;

    public static Snapshot? ReadIfChanged(DatabaseSource source, Query query, CancellationToken cancellation,
        (string Identity, long Revision)? knownStamp, FindingPolicy? policy = null)
    {
        // Each background read is bounded, cancellable, and releases its connection promptly.
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        using var revisionCommand = connection.CreateCommand();
        revisionCommand.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 2 : 5;
        revisionCommand.CommandText = $"SELECT * FROM {source.Prefix}metadata WHERE id=1";
        (string Identity, long Revision) stamp;
        using (var reader = revisionCommand.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            if (!reader.ReadAsync(cancellation).GetAwaiter().GetResult())
                throw new InvalidDataException("Journal revision is unavailable.");
            stamp = (source.Provider == DatabaseProvider.Sqlite ? (string)reader["database_id"] : "server",
                ObservationRevision(reader));
        }
        if (stamp == knownStamp)
            return null;

        using var command = connection.CreateCommand();
        command.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 2 : query.Search.Length > 0 ? 30 : 5;
        var where = ObservationSql.Where(source, query, command);
        var cursor = source.Provider == DatabaseProvider.SqlServer ?
            "c.first_us<=@time AND (c.first_us<@time OR c.id<@id)" : "(c.first_us,c.id)<(@time,@id)";
        command.CommandText = $"""
            SELECT {(source.Provider == DatabaseProvider.SqlServer ? $"TOP ({query.PageSize + 1}) " : "")}
                c.*,s.computer_name
            FROM {source.Prefix}connections c JOIN {source.Prefix}capture_sessions s ON s.id=c.run_id
            WHERE {cursor} AND {where}
            ORDER BY c.first_us DESC,c.id DESC
            {(source.Provider == DatabaseProvider.SqlServer ? "" : $"LIMIT {query.PageSize + 1}")}
            """;
        DatabaseSource.AddParameter(command, "@time", query.Before.Time);
        DatabaseSource.AddParameter(command, "@id", query.Before.Id);
        using var registration = cancellation.Register(command.Cancel);
        if (query.PageSize is < 50 or > 2000)
            throw new ArgumentOutOfRangeException(nameof(query), "Page size must be between 50 and 2000.");
        var rows = new List<ConnectionRow>(query.PageSize + 1);
        using (var reader = command.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            while (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                cancellation.ThrowIfCancellationRequested();
                string Text(string name) => reader.IsDBNull(reader.GetOrdinal(name)) ? "" : reader[name].ToString()!;
                long Number(string name) => Convert.ToInt64(reader[name]);
                var ipv6 = Number("ip_version") == 6;
                string Address(string name) => (ipv6 ? "[" + Text(name + "_address") + "]" :
                    Text(name + "_address")) + ":" + Text(name + "_port");
                string Owner(string side)
                {
                    var pid = Text(side + "_pid");
                    if (pid.Length == 0)
                        return "";
                    var name = Text(side + "_process");
                    return (name.Length == 0 ? "Unknown process" : name) + " (" + pid + ")";
                }
                var sourceOwner = Owner("source");
                var destinationOwner = Owner("destination");
                var process = string.Join(" / ", new[] { sourceOwner, destinationOwner }.Where(s => s.Length != 0));
                var time = DateTimeOffset.FromUnixTimeMilliseconds(Number("first_us") / 1000).ToLocalTime();
                var tls = Text("tls_name");
                var sni = Text("sni");
                var ech = Number("ech_offered") != 0;
                var state = Text("state") switch
                {
                    "hellos_observed" => "ClientHello + ServerHello",
                    "server_hello_only" => "ServerHello",
                    "retry_only" => "HelloRetryRequest",
                    "client_hello_only" => "ClientHello",
                    "ssh_identification" => "SSH identification",
                    "ssh_kex_offers" => "SSH algorithm offers",
                    "ssh_kex_selection" => "SSH algorithm selection",
                    "ssh_newkeys_observed" => "SSH NEWKEYS observed",
                    "ssh_no_common_algorithm" => "SSH has no common algorithm",
                    "wireguard_initiation" => "WireGuard initiation",
                    "wireguard_response" => "WireGuard response",
                    "wireguard_cookie_reply" => "WireGuard cookie reply",
                    "ike_sa_offers" => "IKEv2 SA offers",
                    "ike_sa_selection" => "IKEv2 SA selection",
                    "openvpn_control" => "OpenVPN control",
                    "openvpn_tls_client_hello" => "OpenVPN ClientHello",
                    "openvpn_tls_hellos" => "OpenVPN TLS hellos",
                    "smb_negotiation" => "SMB negotiation",
                    "smb_authentication" => "SMB authentication",
                    "smb_rpc_bind" => "SMB pipe RPC bind",
                    "smb_signed_message" => "SMB signed message",
                    "smb_rdma_signed_payload" => "SMB RDMA signed payload",
                    "smb_compressed_transform" => "SMB compressed message",
                    "smb_encrypted_transform" => "SMB encrypted message",
                    "rdp_negotiation" => "RDP negotiation",
                    "rdp_security_exchange" => "RDP security exchange",
                    "ldap_datagram" => "LDAP datagram",
                    "http_authentication" => "HTTP authentication",
                    "http_observed" => "HTTP — unencrypted",
                    "http_tunnel" => "HTTP CONNECT tunnel",
                    "database_negotiation" => "Database negotiation",
                    "ipsec_headers_observed" => "IPsec headers observed",
                    "rpc_bind" => "DCE/RPC bind",
                    "cleartext_login" => "Cleartext login",
                    "ikev1_sa_offers" => "IKEv1 SA offers",
                    "ikev1_sa_selection" => "IKEv1 SA selection",
                    "ikev1_key_exchange" => "IKEv1 key exchange",
                    "ikev1_auth_payload" => "IKEv1 authentication payload",
                    "ikev1_protected_exchange" => "IKEv1 protected exchange",
                    "ikev1_quick_mode" => "IKEv1 Quick Mode",
                    "tds_prelogin" => "TDS PRELOGIN",
                    "tds_authentication" => "TDS authentication",
                    "tds_framing" => "TDS framing",
                    "kerberos_request" => "Kerberos request",
                    "kerberos_reply" => "Kerberos reply",
                    "kerberos_error" => "Kerberos error",
                    "ldap_bind_request" => "LDAP bind request",
                    "ldap_bind_response" => "LDAP bind response",
                    "ldap_starttls" => "LDAP StartTLS",
                    "possible_encryption" => "Possible encryption",
                    _ => Text("state")
                };
                var row = new ConnectionRow(Number("id"), Number("first_us"), time.ToString("HH:mm:ss.fff"),
                    Address("source"), Address("destination"), Display(tls), Display(Text("cipher_name")),
                    sni.Length == 0 ? "—" : sni + (ech ? " [ECH]" : ""),
                    process.Length == 0 ? "Unattributed" : process, state);
                rows.Add(ObservationDetails.Enrich(row, Text, policy));
            }
        }

        var health = ReadHealth(source, connection, cancellation);
        var hasMore = rows.Count > query.PageSize;
        if (hasMore)
            rows.RemoveAt(query.PageSize);
        return new Snapshot(rows, hasMore, health.Health, health.Diagnostics, stamp);
    }

    public static CaptureHealth ReadHealth(DatabaseSource source, CancellationToken cancellation)
    {
        using var connection = source.OpenConnectionAsync(cancellation).GetAwaiter().GetResult();
        source.Validate(connection, cancellation);
        return ReadHealth(source, connection, cancellation);
    }

    private static CaptureHealth ReadHealth(DatabaseSource source, DbConnection connection,
        CancellationToken cancellation)
    {
        // Report the latest session's heartbeat so a crashed collector cannot appear live indefinitely.
        using var healthCommand = connection.CreateCommand();
        healthCommand.CommandTimeout = source.Provider == DatabaseProvider.Sqlite ? 2 : 5;
        healthCommand.CommandText = $"SELECT {(source.Provider == DatabaseProvider.SqlServer ? "TOP (1) " : "")}* " +
            $"FROM {source.Prefix}capture_sessions ORDER BY started_us DESC " +
            (source.Provider == DatabaseProvider.SqlServer ? "" : "LIMIT 1");
        var health = "No capture sessions";
        var diagnostics = "No capture health data is available.";
        using (var healthRegistration = cancellation.Register(healthCommand.Cancel))
        using (var healthReader = healthCommand.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult())
        {
            if (healthReader.ReadAsync(cancellation).GetAwaiter().GetResult())
            {
                string Text(string name) => healthReader[name].ToString()!;
                long Number(string name) => Convert.ToInt64(healthReader[name]);
                var status = Text("status");
                var age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - Number("updated_us") / 1000;
                if (status == "running" && age > 10000)
                    status = "No recent heartbeat";
                var lost = Number("capture_lost") + Number("queue_lost") + Number("storage_lost") +
                    Number("process_events_lost") + Number("telemetry_lost");
                health = $"Latest session: {status}  •  {Number("packets"):N0} packets  •  " +
                    $"{lost:N0} losses / source errors";
                diagnostics = $"""
                    Source: {Text("source")}
                    Process attribution: {Text("process_status")}
                    Status: {status}
                    Packets processed: {Number("packets"):N0}    •    Bytes: {Number("bytes"):N0}
                    Capture losses: {Number("capture_lost"):N0}
                    Packet queue losses: {Number("queue_lost"):N0}
                    Database queue losses: {Number("storage_lost"):N0}
                    Truncated packets: {Number("truncated"):N0}
                    Malformed packets / handshakes: {Number("malformed"):N0}
                    IP fragment packets: {Number("fragments"):N0}
                    Unsupported packets / capture layers: {Number("unsupported"):N0}
                    Flow admission limit: {Number("flow_limit"):N0}
                    Reassembly / inspection limits: {Number("reassembly_limit"):N0}
                    Process event loss / lookup errors: {Number("process_events_lost"):N0}
                    Endpoint telemetry losses / source errors: {Number("telemetry_lost"):N0}
                    Active tracked flows: {Number("active_flows"):N0}
                    Buffered protocol inspection data: {Number("buffered_bytes") / 1048576.0:N1} MiB
                    """;
            }
        }
        if (source.Provider == DatabaseProvider.Sqlite)
        {
            using var retention = connection.CreateCommand();
            retention.CommandTimeout = 2;
            retention.CommandText = "SELECT count(*) FROM sqlite_schema WHERE name='retention_state'";
            if (Convert.ToInt64(retention.ExecuteScalarAsync(cancellation).GetAwaiter().GetResult()) != 0)
            {
                retention.CommandText = "SELECT * FROM retention_state WHERE id=1";
                using var reader = retention.ExecuteReaderAsync(cancellation).GetAwaiter().GetResult();
                if (reader.ReadAsync(cancellation).GetAwaiter().GetResult())
                {
                    var blocked = Convert.ToInt64(reader["blocked"]) != 0;
                    var days = Convert.ToInt64(reader["days"]);
                    var bytes = Convert.ToInt64(reader["max_bytes"]);
                    diagnostics += $"\nRetention age: {(days == 0 ? "Disabled" : $"{days:N0} days")}" +
                        $"\nRetention size target: {(bytes == 0 ? "Disabled" : $"{bytes / 1048576.0:N0} MiB")}" +
                        $"\nLive journal pages: {Convert.ToInt64(reader["live_bytes"]) / 1048576.0:N1} MiB" +
                        $"\nPruned connections: {Convert.ToInt64(reader["deleted_connections"]):N0}" +
                        $"\nPruned endpoint events: {Convert.ToInt64(reader["deleted_events"]):N0}" +
                        "\nRetention: " + (blocked ? "Size target exceeded; active data or pending uploads protected" :
                            "Protects active data and pending uploads");
                    if (blocked)
                        health += "  •  Retention blocked";
                }
            }
        }
        return new(health, diagnostics);
    }

    private static string Display(string value) => value.Length == 0 ? "Not observed" : value;
}
