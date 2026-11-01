using System.Text.Json;
using Microsoft.Data.Sqlite;

internal static class SourceRestoration
{
    public static async Task VerifyAsync(string publisher, string collector, string seed, string output,
        Func<string, string[], Task<(int Exit, string Text)>> run, Action<bool, string> check)
    {
        var outcomes = new List<(bool Passed, string Description)>();
        foreach (var scenario in new[] { "rollback", "identity", "contention" })
        {
            var path = Path.Combine(output, $"publisher-{scenario}.db");
            var backup = Path.Combine(output, $"publisher-{scenario}-backup.db");
            void Copy(string from, string to)
            {
                using var source = new SqliteConnection(new SqliteConnectionStringBuilder
                    { DataSource = from, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
                using var destination = new SqliteConnection(new SqliteConnectionStringBuilder
                    { DataSource = to, Pooling = false }.ToString());
                source.Open();
                destination.Open();
                source.BackupDatabase(destination);
            }
            void Modify(string file, string sql)
            {
                using var connection = new SqliteConnection($"Data Source={file};Pooling=False");
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
            long Scalar(string sql)
            {
                using var connection = new SqliteConnection($"Data Source={path};Pooling=False");
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = sql;
                return Convert.ToInt64(command.ExecuteScalar());
            }
            Copy(seed, path);
            Modify(path, """
                PRAGMA journal_mode=WAL;
                BEGIN IMMEDIATE;
                UPDATE metadata SET database_id=lower(hex(randomblob(16))),revision=100,observation_revision=100;
                UPDATE connections SET first_us=1,last_us=2,ended_us=2,change_revision=100;
                UPDATE capture_sessions SET started_us=1,updated_us=2,stopped_us=2,change_revision=100;
                UPDATE endpoint_events SET timestamp_us=2,change_revision=100;
                UPDATE certificates SET change_revision=100;
                UPDATE connection_certificates SET change_revision=100;
                DROP TABLE IF EXISTS publishing_cursors;
                DROP TABLE IF EXISTS replication_consumers;
                COMMIT;
                """);
            var rows = Scalar("SELECT count(*) FROM connections");
            await using var receiver = new Receiver(null);
            var sending = run(publisher, ["--source", path, "--syslog", $"tcp://localhost:{receiver.Port}",
                "--allow-plaintext-syslog", "--events", "connections", "--max-events-per-second", "50", "--once"]);
            try
            {
                // Receiving an event proves that the first batch released its source snapshot before restoration.
                await receiver.Until(() => receiver.Messages.Count > 0 || sending.IsCompleted);
                if (receiver.Messages.IsEmpty)
                    throw new InvalidOperationException("The publisher did not deliver its first snapshot.");
                if (scenario == "rollback")
                {
                    Copy(path, backup);
                    Modify(backup, """
                        UPDATE metadata SET revision=1,observation_revision=1;
                        UPDATE connections SET sni='restored-not-published.test',change_revision=1;
                        UPDATE capture_sessions SET change_revision=1;
                        UPDATE endpoint_events SET change_revision=1;
                        UPDATE certificates SET change_revision=1;
                        UPDATE connection_certificates SET change_revision=1;
                        """);
                    Copy(backup, path);
                }
                else
                {
                    using var writer = new SqliteConnection($"Data Source={path};Pooling=False");
                    writer.Open();
                    using var transaction = writer.BeginTransaction();
                    using var command = writer.CreateCommand();
                    command.Transaction = transaction;
                    command.CommandText = scenario == "identity" ? """
                        UPDATE metadata SET database_id=lower(hex(randomblob(16))),revision=1,observation_revision=1;
                        UPDATE connections SET sni='restored-not-published.test',change_revision=1;
                        UPDATE capture_sessions SET change_revision=1;
                        UPDATE endpoint_events SET change_revision=1;
                        UPDATE certificates SET change_revision=1;
                        UPDATE connection_certificates SET change_revision=1;
                        UPDATE publishing_cursors SET database_id=(SELECT database_id FROM metadata);
                        """ : "UPDATE metadata SET revision=101";
                    command.ExecuteNonQuery();

                    // Hold the writer while delivery completes so acknowledgement waits behind the source change.
                    await receiver.Until(() => receiver.Messages.Count >= 128 || sending.IsCompleted);
                    await Task.Delay(300);
                    transaction.Commit();
                }
            }
            finally
            {
                // The process runner has its own deadline and releases the child even when fixture setup fails.
                try { await sending; }
                catch { }
            }
            var result = await sending;
            var acknowledged = Scalar("SELECT min(acknowledged_revision) FROM replication_consumers");
            var empty = Path.Combine(output, $"publisher-{scenario}-empty.pcap");
            Fixtures.Pcap(empty, false);
            var remaining = rows;
            for (;;)
            {
                var maintenance = await run(collector, ["--db", path, "--replay", empty, "--no-process",
                    "--retention-days", "1", "--retention-mb", "0", "--replication-required"]);
                if (maintenance.Exit != 0)
                    throw new InvalidOperationException("Publisher retention verification failed: " + maintenance.Text);
                var count = Scalar("SELECT count(*) FROM connections");
                if (count == remaining)
                    break;
                remaining = count;
            }
            var initialMessages = receiver.Messages.Count;
            int? recoveryExit = null;
            long? recoveryAcknowledgement = null;
            var recovered = 0;
            if (scenario != "contention" && result.Exit != 0 && acknowledged == 0 && remaining == rows)
            {
                // Restart from the restored journal's own durable cursor and deliver its retained snapshots.
                var retry = await run(publisher, ["--source", path, "--syslog", $"tcp://localhost:{receiver.Port}",
                    "--allow-plaintext-syslog", "--events", "connections", "--once"]);
                await receiver.Until(() => receiver.Messages.Count >= initialMessages + rows);
                recovered = receiver.Messages.Skip(initialMessages).Select(Receiver.Envelope)
                    .Count(value => value.GetProperty("revision").GetInt64() == 1);
                recoveryExit = retry.Exit;
                recoveryAcknowledgement = Scalar("SELECT min(acknowledged_revision) FROM replication_consumers");
                outcomes.Add((retry.Exit == 0 && recovered == rows && recoveryAcknowledgement >= 1,
                    $"The {scenario} source resumes delivery from its restored cursor"));
            }
            File.WriteAllText(Path.Combine(output, $"publisher-{scenario}.json"), JsonSerializer.Serialize(new
            {
                scenario,
                publisher_exit = result.Exit,
                original_revision = 100,
                restored_revision = scenario == "contention" ? 101 : 1,
                acknowledged_revision = acknowledged,
                connections = rows,
                retained_connections = remaining,
                messages = initialMessages,
                recovery_exit = recoveryExit,
                recovered_connections = recovered,
                recovery_acknowledged_revision = recoveryAcknowledgement
            }, new JsonSerializerOptions { WriteIndented = true }));
            outcomes.Add((scenario == "contention" ? result.Exit == 0 && acknowledged == 101 && remaining == 0 &&
                receiver.Messages.Count == rows : result.Exit != 0 && acknowledged == 0 && remaining == rows,
                scenario == "contention" ? "Ordinary writer contention preserves complete publisher delivery" :
                    $"Source {scenario} during publication cannot acknowledge or prune restored history"));
        }
        foreach (var outcome in outcomes)
            check(outcome.Passed, outcome.Description);
    }
}
