using System.Buffers.Binary;
using Microsoft.Data.Sqlite;

internal static class Fixtures
{
    public static void Heartbeat(string path, bool running, long losses = 0)
    {
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            BEGIN IMMEDIATE;
            UPDATE metadata SET revision=revision+1;
            UPDATE capture_sessions SET status=@status,packets=packets+1,capture_lost=@losses,
                change_revision=(SELECT revision FROM metadata) WHERE started_us=1;
            COMMIT;
            """;
        command.Parameters.AddWithValue("@status", running ? "running" : "stopped");
        command.Parameters.AddWithValue("@losses", losses);
        command.ExecuteNonQuery();
    }

    public static void Pcap(string path, bool hellos)
    {
        using var writer = new BinaryWriter(File.Create(path));
        foreach (var value in new uint[] { 0xA1B2C3D4, 0x00040002, 0, 0, 65535, 101 })
            writer.Write(value);
        if (!hellos)
            return;
        foreach (var client in new[] { true, false })
        {
            var body = new List<byte> { 3, 3 };
            body.AddRange(new byte[32]);
            body.Add(0);
            body.AddRange(client ? [0, 2, 0xC0, 0x2F, 1, 0, 0, 0] : [0xC0, 0x2F, 0, 0, 0]);
            var record = new List<byte> { 22, 3, 3, 0, (byte)(body.Count + 4), (byte)(client ? 1 : 2),
                0, 0, (byte)body.Count };
            record.AddRange(body);
            var packet = new byte[40 + record.Count];
            packet[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
            packet[8] = 64;
            packet[9] = 6;
            new byte[] { 192, 0, 2, (byte)(client ? 1 : 2), 192, 0, 2, (byte)(client ? 2 : 1) }.CopyTo(packet, 12);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), client ? (ushort)50000 : (ushort)443);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), client ? (ushort)443 : (ushort)50000);
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24), client ? 1000U : 9000U);
            packet[32] = 0x50;
            packet[33] = 0x18;
            record.CopyTo(packet, 40);
            writer.Write(100U);
            writer.Write(client ? 0U : 1000U);
            writer.Write((uint)packet.Length);
            writer.Write((uint)packet.Length);
            writer.Write(packet);
        }
    }

    public static void Expand(string path)
    {
        using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(connections)";
        var columns = new List<string>();
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                if (reader.GetString(1) != "id")
                    columns.Add(reader.GetString(1));
        command.CommandText = """
            UPDATE metadata SET revision=revision+1;
            UPDATE capture_sessions SET started_us=1,updated_us=2,stopped_us=2;
            UPDATE connections SET first_us=1,last_us=2,ended_us=2;
            """;
        command.ExecuteNonQuery();
        command.CommandText = "WITH RECURSIVE copies(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM copies WHERE n<300) " +
            "INSERT INTO connections(" + string.Join(',', columns) + ") SELECT " +
            string.Join(',', columns.Select(column => column == "flow_id" ? "c.flow_id+n" : "c." + column)) +
            " FROM (SELECT * FROM connections LIMIT 1) c CROSS JOIN copies";
        command.ExecuteNonQuery();
        command.CommandText = """
            UPDATE connections SET change_revision=(SELECT revision FROM metadata);
            UPDATE connections SET sni=@unicode,source_process=@unicode,source_path=@unicode,
                destination_process=@unicode,destination_path=@unicode WHERE id=(SELECT min(id) FROM connections);
            UPDATE connections SET sni='publishing.test'||char(13)||char(10)||'<132>1 forged-header'
                WHERE id=(SELECT min(id)+1 FROM connections);
            INSERT INTO endpoint_events(id,run_id,timestamp_us,provider,kind,result,pid,peer,port,protocol,cipher,
                certificate_id,detail_json,change_revision)
                SELECT 'publishing-test',id,2,'Test adapter','TLS','Endpoint reported handshake failure',1234,
                    '192.0.2.2',443,'TLS 1.2','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','','{"success":false}',
                    (SELECT revision FROM metadata) FROM capture_sessions LIMIT 1;
            UPDATE capture_sessions SET change_revision=(SELECT revision FROM metadata);
            """;
        command.Parameters.AddWithValue("@unicode", new string('界', 1024) + "\nforged-header");
        command.ExecuteNonQuery();
    }
}
