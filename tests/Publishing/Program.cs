using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Cipherazzi.Data;
using System.Xml.Linq;

SQLitePCL.Batteries_V2.Init();
var publisher = Path.GetFullPath(args[0]);
var collector = Path.GetFullPath(args[1]);
var output = Path.GetFullPath(args[2]);
var windows = args.Contains("--windows-events");
Directory.CreateDirectory(output);
var checks = new List<string>();
var source = "Cipherazzi-Publishing-Test-" + Guid.NewGuid().ToString("N")[..12];
var registered = false;
var journal = Path.Combine(output, "publishing.db");
if (File.Exists(journal))
    throw new ArgumentException("Choose an output directory without an existing publishing.db.");
var pcap = Path.Combine(output, "hello.pcap");
var emptyPcap = Path.Combine(output, "empty.pcap");
var ca = Path.Combine(output, "syslog-ca.pem");
var metrics = new List<object>();

void Check(bool condition, string text)
{
    if (!condition)
        throw new InvalidOperationException(text);
    checks.Add(text);
    Console.WriteLine("Passed: " + text);
}

Task<(int Exit, string Text)> Run(string executable, params string[] arguments) => RunProcess(executable, arguments);

async Task<(int Exit, string Text)> RunProcess(string executable, string[] arguments,
    TaskCompletionSource? ready = null)
{
    var start = new ProcessStartInfo(executable)
    {
        RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
    };
    foreach (var argument in arguments)
        start.ArgumentList.Add(argument);
    using var process = Process.Start(start)!;
    _ = process.Handle;
    async Task<string> ReadOutput()
    {
        if (ready is null)
            return await process.StandardOutput.ReadToEndAsync();
        var first = await process.StandardOutput.ReadLineAsync();
        if (first?.StartsWith("Publishing started: ", StringComparison.Ordinal) == true)
            ready.TrySetResult();
        else
            ready.TrySetException(new InvalidOperationException("The publisher did not report successful startup."));
        return first + Environment.NewLine + await process.StandardOutput.ReadToEndAsync();
    }
    var stdout = ReadOutput();
    var stderr = process.StandardError.ReadToEndAsync();
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(40));
    var peak = 0L;
    var elapsed = Stopwatch.StartNew();
    double? startupCpu = null;
    double? startupElapsed = null;
    try
    {
        while (!process.HasExited)
        {
            process.Refresh();
            try { peak = Math.Max(peak, process.WorkingSet64); }
            catch (InvalidOperationException) when (process.HasExited) {}
            if (startupCpu is null && elapsed.ElapsedMilliseconds >= 2000 && !process.HasExited)
            {
                startupCpu = process.TotalProcessorTime.TotalMilliseconds;
                startupElapsed = elapsed.Elapsed.TotalMilliseconds;
            }
            await Task.Delay(10, timeout.Token);
        }
        await process.WaitForExitAsync(timeout.Token);
    }
    catch { process.Kill(true); throw; }
    metrics.Add(new { executable = Path.GetFileName(executable), arguments, process.ExitCode,
        elapsed_ms = elapsed.Elapsed.TotalMilliseconds, cpu_ms = process.TotalProcessorTime.TotalMilliseconds,
        peak_bytes = peak, cpu_after_startup_ms = startupCpu is null ? (double?)null :
            process.TotalProcessorTime.TotalMilliseconds - startupCpu,
        elapsed_after_startup_ms = startupElapsed is null ? (double?)null :
            elapsed.Elapsed.TotalMilliseconds - startupElapsed });
    var text = await stdout + await stderr;
    File.AppendAllText(Path.Combine(output, "commands.log"), executable + " " + string.Join(' ', arguments) +
        Environment.NewLine + text + Environment.NewLine);
    return (process.ExitCode, text);
}

long Scalar(string sql)
{
    using var connection = new SqliteConnection($"Data Source={journal};Pooling=False");
    connection.Open();
    using var command = connection.CreateCommand();
    command.CommandText = sql;
    return Convert.ToInt64(command.ExecuteScalar());
}

try
{
    // Seed real parser output, then exercise many records sharing one committed revision.
    Fixtures.Pcap(pcap, true);
    Fixtures.Pcap(emptyPcap, false);
    var seeded = await Run(collector, "--replay", pcap, "--db", journal, "--no-process");
    Check(seeded.Exit == 0 && Scalar("SELECT count(*) FROM connections") == 1, "The seed is real collector output");
    Fixtures.Expand(journal);
    var rows = Scalar("SELECT count(*) FROM connections");
    using var rsa = RSA.Create(2048);
    var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(
        X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, true));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
        [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], false));
    var names = new SubjectAlternativeNameBuilder();
    names.AddDnsName("localhost");
    request.CertificateExtensions.Add(names.Build());
    using var generated = request.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
    using var certificate = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
    File.WriteAllText(ca, certificate.ExportCertificatePem());
    await using var receiver = new Receiver(certificate, Path.Combine(output, "receiver-errors.txt"));
    var destination = $"tls://localhost:{receiver.Port}";
    var windowsArguments = windows ? new[] { "--windows-events", "--windows-event-source", source } : [];
    if (windows)
    {
        var registration = await Run(publisher, "--register-event-source", "--windows-event-source", source,
            "--event-message-file", collector);
        Check(registration.Exit == 0, "The event source accepts the collector's message resources");
        registered = true;
    }
    var rejected = await Run(publisher, ["--source", journal, "--syslog", destination, "--once", ..windowsArguments]);
    Check(rejected.Exit != 0 && receiver.Messages.IsEmpty,
        "An untrusted TLS receiver is rejected without publishing metadata");
    Check(Scalar("SELECT min(acknowledged_revision) FROM replication_consumers") == 0,
        "An unavailable destination retains its upload protection");
    if (windows)
        Check(Scalar("SELECT max(acknowledged_revision) FROM replication_consumers") > 0,
            "Windows publishing advances independently while syslog is unavailable");
    var protectedReplay = await Run(collector, "--db", journal, "--replay", emptyPcap, "--no-process",
        "--retention-days", "1", "--retention-mb", "1");
    Check(protectedReplay.Exit == 0 && Scalar("SELECT count(*) FROM connections") == rows,
        "Automatic retention preserves records pending publication");
    var published = await Run(publisher, ["--source", journal, "--syslog", destination, "--syslog-ca", ca,
        "--once", ..windowsArguments]);
    Check(published.Exit == 0, "TLS publishing resumes with a private connection-local CA");
    await receiver.Until(() => receiver.Messages.Count >= rows + 3);
    var messages = receiver.Messages.ToArray();
    var envelopes = messages.Select(Receiver.Envelope).ToArray();
    Check(envelopes.Count(value => value.GetProperty("type").GetString() == "connection") == rows &&
        envelopes.Select(value => value.GetProperty("id").GetString()).Distinct().Count() == envelopes.Length,
        "Bounded pages publish every record in a large shared revision exactly once in a completed run");
    Check(envelopes.All(value => value.GetProperty("schema").GetString() == "cipherazzi.event/1") &&
        messages.All(value => Encoding.UTF8.GetByteCount(value) < 17000 &&
            !value.Contains('\r') && !value.Contains('\n')) &&
        envelopes.Any(value => value.TryGetProperty("truncated", out var flag) && flag.GetBoolean()) &&
        envelopes.Any(value => value.GetProperty("type").GetString() == "connection" &&
            value.GetProperty("payload").GetProperty("sni").GetString()
                ?.Contains("\r\n", StringComparison.Ordinal) == true),
        "Structured Unicode metadata remains valid and bounded with explicit truncation");
    var resumed = await Run(publisher, ["--source", journal, "--syslog", destination, "--syslog-ca", ca,
        "--once", ..windowsArguments]);
    Check(resumed.Exit == 0 && receiver.Messages.Count == messages.Length,
        "A restart at the durable cursor does not replay an already published batch");
    var idle = await Run(publisher, ["--source", journal, "--syslog", destination, "--syslog-ca", ca,
        "--duration", "12", ..windowsArguments]);
    Check(idle.Exit == 0 && receiver.Messages.Count == messages.Length,
        "An idle publisher polls without repeating acknowledged events and stops cleanly");
    var wrongHost = $"tls://127.0.0.1:{receiver.Port}";
    var mismatch = await Run(publisher, "--source", journal, "--syslog", wrongHost, "--syslog-ca", ca, "--once");
    Check(mismatch.Exit != 0 && receiver.Messages.Count == messages.Length,
        "A private CA does not bypass syslog hostname verification");
    Check((await Run(publisher, "--source", journal, "--syslog", wrongHost, "--unregister")).Exit == 0,
        "A retired destination can release its publishing cursor and retention protection");

    // Use a temporary personal certificate, leaving the machine/user trust stores unchanged.
    using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
    {
        store.Open(OpenFlags.ReadWrite);
        store.Add(certificate);
        try
        {
            await using var mutual = new Receiver(certificate, Path.Combine(output, "mutual-errors.txt"),
                certificate.Thumbprint);
            var mutualDestination = $"tls://localhost:{mutual.Port}";
            var authentication = await Run(publisher, "--source", journal, "--syslog", mutualDestination,
                "--syslog-ca", ca, "--client-certificate", certificate.Thumbprint, "--once");
            await mutual.Until(() => mutual.Messages.Count >= rows + 3);
            Check(authentication.Exit == 0 && mutual.AuthenticatedClients > 0,
                "Mutual TLS uses the running account's personal certificate store by default");
            Check((await Run(publisher, "--source", journal, "--syslog", mutualDestination,
                "--client-certificate", certificate.Thumbprint, "--certificate-store", "LocalMachine", "--once"))
                .Exit != 0, "Publisher rejects machine-scoped client credentials");
            await Run(publisher, "--source", journal, "--syslog", mutualDestination, "--unregister");
        }
        finally { store.Remove(certificate); }
    }

    // Validate explicit plaintext opt-in, event filtering, and interrupted-batch replay against a real socket.
    await using var plain = new Receiver(null);
    var tcp = $"tcp://localhost:{plain.Port}";
    var plaintextRejected = await Run(publisher, "--source", journal, "--syslog", tcp, "--once");
    Check(plaintextRejected.Exit != 0 && plain.Messages.IsEmpty,
        "Plaintext syslog is disabled without explicit opt-in");
    var filtered = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "endpoints", "--once");
    await plain.Until(() => plain.Messages.Count == 1);
    Check(filtered.Exit == 0 &&
        Receiver.Envelope(plain.Messages.Single()).GetProperty("type").GetString() == "endpoint",
        "Event-kind filtering is applied before publication");
    await Run(publisher, "--source", journal, "--syslog", tcp, "--unregister", "--allow-plaintext-syslog");
    plain.DropNextConnectionAfterOneMessage = true;
    var beforeInterrupted = plain.Messages.Count;
    var interrupted = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "connections", "--max-events-per-second", "20", "--once");
    Check(interrupted.Exit != 0 && Scalar("SELECT min(acknowledged_revision) FROM replication_consumers") == 0,
        "A failed partial batch does not advance its durable acknowledgement");
    var beforeRetry = plain.Messages.Count;
    var interruptedIds = plain.Messages.Skip(beforeInterrupted).Select(Receiver.Envelope)
        .Select(value => value.GetProperty("id").GetString()).ToHashSet(StringComparer.Ordinal);
    var retry = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "connections", "--once");
    await plain.Until(() => plain.Messages.Count >= beforeRetry + rows);
    var retriedIds = plain.Messages.Skip(beforeRetry).Select(Receiver.Envelope)
        .Select(value => value.GetProperty("id").GetString()).ToHashSet(StringComparer.Ordinal);
    Check(retry.Exit == 0 && retriedIds.Count == rows && interruptedIds.Count > 0 &&
        interruptedIds.IsSubsetOf(retriedIds),
        "Retry preserves event IDs and completes the interrupted batch");
    await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog", "--unregister");

    // Exercise live tailing, duplicate-instance exclusion, and health coalescing without restarting collection.
    var skipped = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "health", "--start-now", "--once");
    var beforeTail = plain.Messages.Count;
    Check(skipped.Exit == 0, "A new destination can start at the current journal revision");
    var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var tail = RunProcess(publisher, ["--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "health", "--poll-ms", "100", "--health-seconds", "5", "--duration", "8"], ready);
    await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
    var duplicate = await Run(publisher, "--source", journal, "--syslog", tcp,
        "--allow-plaintext-syslog", "--once");
    Check(duplicate.Exit != 0 && duplicate.Text.Contains("already using", StringComparison.Ordinal),
        "A duplicate publisher cannot use the same journal and destination");
    Check(plain.Messages.Count == beforeTail, "Starting at the current revision does not backfill history");
    Fixtures.Heartbeat(journal, true);
    await plain.Until(() => plain.Messages.Count > beforeTail);
    for (var attempt = 0; attempt < 30; attempt++)
    {
        Fixtures.Heartbeat(journal, true);
        await Task.Delay(30);
    }
    var beforeWarning = plain.Messages.Count;
    Fixtures.Heartbeat(journal, true, 1);
    await plain.Until(() => plain.Messages.Count > beforeWarning);
    Check(plain.Messages.Last().StartsWith("<132>1", StringComparison.Ordinal),
        "New capture losses publish a warning without waiting for the health interval");
    var beforeStopped = plain.Messages.Count;
    Fixtures.Heartbeat(journal, false, 1);
    await plain.Until(() => plain.Messages.Count > beforeStopped);
    Check(Receiver.Envelope(plain.Messages.Last()).GetProperty("payload")
        .GetProperty("status").GetString() == "stopped",
        "A capture status change bypasses health throttling");
    var tailed = await tail;
    Check(tailed.Exit == 0 && plain.Messages.Count - beforeTail is >= 3 and <= 5,
        "Live health changes are coalesced and a timed publisher stops cleanly");
    Fixtures.Heartbeat(journal, false);
    await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog", "--unregister");

    // Policy delivery uses the actual publisher, parser journal, and receiver across updates and restarts.
    var policyFile = Path.Combine(output, "background-policies.config");
    var policies = new[]
    {
        new CryptoPolicy { Name = "Migration" },
        new CryptoPolicy { Name = "Completion", RequirePostQuantumKeyExchange = false },
        new CryptoPolicy { Name = "Version", RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false },
        new CryptoPolicy { Name = "Strong TLS", MinimumTls = 772,
            RequirePostQuantumKeyExchange = false, RequireEndpointCompletion = false }
    };
    new XDocument(new XElement("cipherazzi", new XElement("policies", policies.Select(policy => policy.ToXml()))))
        .Save(policyFile);
    var beforePolicies = plain.Messages.Count;
    var policyPublished = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "policies", "--policies", policyFile, "--once");
    await plain.Until(() => plain.Messages.Count >= beforePolicies + rows * policies.Length);
    var policyEvents = plain.Messages.Skip(beforePolicies).Select(Receiver.Envelope).ToArray();
    Check(policyPublished.Exit == 0 && policyEvents.Length == rows * policies.Length &&
        policyEvents.All(value => value.GetProperty("type").GetString() == "policy") &&
        policyEvents.Select(value => value.GetProperty("payload").GetProperty("status").GetString())
            .ToHashSet().SetEquals(["Pass", "Violation", "Insufficient evidence"]),
        "Background policies distinguish passing, violated, and insufficient evidence across journal pages");
    Check(policyEvents.Select(value => value.GetProperty("id").GetString()).Distinct().Count() == policyEvents.Length &&
        plain.Messages.Skip(beforePolicies).All(value => Encoding.UTF8.GetByteCount(value) < 17000),
        "Policy assessments carry distinct bounded IDs and observable evidence reasons");
    var beforePolicyRestart = plain.Messages.Count;
    var policyResumed = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "policies", "--policies", policyFile, "--once");
    Check(policyResumed.Exit == 0 && plain.Messages.Count == beforePolicyRestart,
        "Policy publishing resumes at its durable cursor without repeating completed assessments");
    await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog", "--unregister");
    plain.DropNextConnectionAfterOneMessage = true;
    var beforePolicyFailure = plain.Messages.Count;
    var failedPolicies = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "policies", "--policies", policyFile, "--max-events-per-second", "20", "--once");
    var failedPolicyIds = plain.Messages.Skip(beforePolicyFailure).Select(Receiver.Envelope)
        .Select(value => value.GetProperty("id").GetString()).ToHashSet();
    var beforePolicyRetry = plain.Messages.Count;
    var retriedPolicies = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "policies", "--policies", policyFile, "--once");
    await plain.Until(() => plain.Messages.Count >= beforePolicyRetry + rows * policies.Length);
    Check(failedPolicies.Exit != 0 && retriedPolicies.Exit == 0 && failedPolicyIds.Count > 0 &&
        failedPolicyIds.IsSubsetOf(plain.Messages.Skip(beforePolicyRetry).Select(Receiver.Envelope)
            .Select(value => value.GetProperty("id").GetString()).ToHashSet()),
        "A partially delivered policy batch retries with the same assessment IDs");
    beforePolicyRestart = plain.Messages.Count;
    using (var connection = new SqliteConnection($"Data Source={journal};Pooling=False"))
    {
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            BEGIN IMMEDIATE;
            UPDATE metadata SET revision=revision+1;
            UPDATE connections SET crypto_json=json_patch(crypto_json,
                '{"group_class":"Hybrid post-quantum","group_standardization":"Standardized",' ||
                '"endpoint_confirmations":[{"success":true,"local_role":"Client","peer_verified":1}]}'),
                change_revision=(SELECT revision FROM metadata) WHERE id=(SELECT min(id) FROM connections);
            COMMIT;
            """;
        command.ExecuteNonQuery();
    }
    var recoveredPolicy = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "policies", "--policies", policyFile, "--once");
    await plain.Until(() => plain.Messages.Count >= beforePolicyRestart + policies.Length);
    Check(recoveredPolicy.Exit == 0 && plain.Messages.Skip(beforePolicyRestart).Select(Receiver.Envelope).Where(value =>
        value.GetProperty("payload").GetProperty("policy").GetString() != "Strong TLS").All(value =>
        value.GetProperty("payload").GetProperty("status").GetString() == "Pass"),
        "New endpoint completion and PQ evidence publish recovery assessments for the changed connection");
    await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog", "--unregister");

    var beforeViolationFilter = plain.Messages.Count;
    var violationsOnly = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "policies", "--policies", policyFile, "--policy-results", "violations", "--once");
    await plain.Until(() => plain.Messages.Count >= beforeViolationFilter + rows);
    Check(violationsOnly.Exit == 0 && plain.Messages.Count == beforeViolationFilter + rows &&
        plain.Messages.Skip(beforeViolationFilter).Select(Receiver.Envelope).All(value =>
            value.GetProperty("payload").GetProperty("status").GetString() == "Violation"),
        "Violation-only policy publishing filters pass and insufficient-evidence assessments");
    using (var connection = new SqliteConnection($"Data Source={journal};Pooling=False"))
    {
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            BEGIN IMMEDIATE;
            UPDATE metadata SET revision=revision+1;
            UPDATE connections SET crypto_json='{broken',change_revision=(SELECT revision FROM metadata)
                WHERE id=(SELECT min(id)+1 FROM connections);
            COMMIT;
            """;
        command.ExecuteNonQuery();
    }
    var beforeDamaged = plain.Messages.Count;
    var damagedPolicy = await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog",
        "--events", "policies", "--policies", policyFile, "--once");
    await plain.Until(() => plain.Messages.Count >= beforeDamaged + policies.Length);
    Check(damagedPolicy.Exit == 0 && plain.Messages.Skip(beforeDamaged).Select(Receiver.Envelope).All(value =>
        value.GetProperty("payload").GetProperty("status").GetString() != "Pass" &&
        value.GetProperty("payload").GetProperty("issues").EnumerateArray().Any(issue =>
            issue.GetProperty("message").GetString()?.Contains("could not be read", StringComparison.Ordinal) == true)),
        "Damaged cryptographic metadata remains insufficient evidence without blocking the publishing cursor");
    await Run(publisher, "--source", journal, "--syslog", tcp, "--allow-plaintext-syslog", "--unregister");

    // Collect an actual failed endpoint-only operation, then assess it without a network observation.
    var endpointReports = Path.Combine(output, "policy-endpoint-reports");
    Directory.CreateDirectory(endpointReports);
    var endpointJournal = Path.Combine(output, "policy-endpoint.db");
    var reportedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000;
    using (var self = Process.GetCurrentProcess())
        File.WriteAllText(Path.Combine(endpointReports, "failure.json"), JsonSerializer.Serialize(new
        {
            schema = "cipherazzi.endpoint/1", provider = "Policy publishing test", pid = Environment.ProcessId,
            process_started_us = new DateTimeOffset(self.StartTime.ToUniversalTime()).ToUnixTimeMilliseconds() * 1000,
            handshake_started_us = reportedAt - 10000, timestamp_us = reportedAt,
            local = new { address = "127.0.0.1", port = 55000 }, remote = new { address = "127.0.0.1", port = 443 },
            role = "client", transport = "TCP", success = false, tls_version = 771
        }));
    var endpointCollected = await Run(collector, "--db", endpointJournal, "--endpoint-only",
        "--endpoint-directory", endpointReports, "--duration", "2", "--no-process");
    var beforeEndpointPolicies = plain.Messages.Count;
    var endpointPolicies = await Run(publisher, "--source", endpointJournal, "--syslog", tcp,
        "--allow-plaintext-syslog", "--events", "policies", "--policies", policyFile, "--once");
    await plain.Until(() => plain.Messages.Count >= beforeEndpointPolicies + policies.Length);
    Check(endpointCollected.Exit == 0 && endpointPolicies.Exit == 0 &&
        plain.Messages.Skip(beforeEndpointPolicies).Select(Receiver.Envelope).All(value =>
            value.GetProperty("payload").GetProperty("observation_id").GetInt64() == 0 &&
            value.GetProperty("payload").GetProperty("endpoint_event_id").GetString()?.Length > 0 &&
            value.GetProperty("payload").GetProperty("evidence_source").GetString() == "Endpoint"),
        "Endpoint-only collection publishes scoped policy evidence without inventing a packet observation");
    await Run(publisher, "--source", endpointJournal, "--syslog", tcp, "--allow-plaintext-syslog", "--unregister");

    if (windows)
    {
        // Deliver policy assessments through their own Event Log destination and message resource.
        var windowsPolicies = await Run(publisher, "--source", journal, "--windows-events",
            "--windows-event-source", source, "--events", "policies", "--policies", policyFile, "--once");
        Check(windowsPolicies.Exit == 0, "Policy assessments reach the Windows Event Log destination");
        var script = "$events=Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='" + source +
            "'}; if (@($events | Where-Object {$_.Id -notin 1001,1002,1003,1004 -or " +
            "!$_.Message.StartsWith('{')}).Count)" +
            " {throw 'An event did not render its registered message.'}; " +
            "if (!@($events | Where-Object {$_.Id -eq 1004}).Count) {throw 'Policy events were not delivered.'}; " +
            "@($events | ForEach-Object {$_.Properties[0].Value | ConvertFrom-Json}) | ConvertTo-Json -Depth 12";
        var rendered = await Run(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell/v1.0/powershell.exe"), "-NoProfile", "-Command", script);
        Check(rendered.Exit == 0 && rendered.Text.Contains("cipherazzi.event/1", StringComparison.Ordinal),
            "Application log events have the expected IDs and render their JSON through Windows message resources");
        using var events = JsonDocument.Parse(rendered.Text);
        Check(events.RootElement.EnumerateArray().Any(item => item.GetProperty("type").GetString() == "policy" &&
            item.GetProperty("payload").GetProperty("status").GetString() is
                "Pass" or "Violation" or "Insufficient evidence"),
            "Rendered Event Log policy assessments retain their actionable status");
        File.WriteAllText(Path.Combine(output, "windows-events.json"), rendered.Text);
        await Run(publisher, "--source", journal, "--windows-events", "--windows-event-source", source, "--unregister");
    }
    var pruning = await Run(collector, "--db", journal, "--replay", emptyPcap, "--no-process",
        "--retention-days", "1", "--retention-mb", "1");
    Check(pruning.Exit == 0 && Scalar("SELECT count(*) FROM connections") < rows,
        "Acknowledged records become eligible for local retention");
    File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        { passed = true, checks, metrics, windows }, new JsonSerializerOptions { WriteIndented = true }));
}
catch (Exception error)
{
    File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        { passed = false, checks, metrics, windows, failure = error.ToString() },
        new JsonSerializerOptions { WriteIndented = true }));
    throw;
}
finally
{
    if (registered)
        Registry.LocalMachine.DeleteSubKeyTree(
            @"SYSTEM\CurrentControlSet\Services\EventLog\Application\" + source, false);
}

internal sealed class Receiver : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly Task reading;
    public ConcurrentQueue<string> Messages { get; } = new();
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    public bool DropNextConnectionAfterOneMessage { get; set; }
    public int AuthenticatedClients { get; private set; }

    public Receiver(X509Certificate2? certificate, string? errorLog = null, string? clientThumbprint = null)
    {
        listener.Start();
        reading = Task.Run(async () =>
        {
            while (!shutdown.IsCancellationRequested)
            {
                try
                {
                    using var client = await listener.AcceptTcpClientAsync(shutdown.Token);
                    using var network = client.GetStream();
                    Stream stream = network;
                    using var tls = certificate is null ? null : new SslStream(network, true,
                        (_, peer, _, _) => clientThumbprint is null ||
                            peer?.GetCertHashString().Equals(clientThumbprint,
                                StringComparison.OrdinalIgnoreCase) == true);
                    if (tls is not null)
                    {
                        await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                            { ServerCertificate = certificate,
                                ClientCertificateRequired = clientThumbprint is not null },
                            shutdown.Token);
                        if (clientThumbprint is not null)
                            AuthenticatedClients++;
                        stream = tls;
                    }
                    var digit = new byte[1];
                    while (await stream.ReadAsync(digit, shutdown.Token) == 1)
                    {
                        var length = 0;
                        var digits = 0;
                        while (digit[0] != ' ')
                        {
                            if (digit[0] is < (byte)'0' or > (byte)'9' || ++digits > 6)
                                throw new InvalidDataException("Invalid octet-count frame.");
                            length = length * 10 + digit[0] - '0';
                            await stream.ReadExactlyAsync(digit, shutdown.Token);
                        }
                        if (length is 0 or > 32768)
                            throw new InvalidDataException("Invalid frame length.");
                        var bytes = new byte[length];
                        await stream.ReadExactlyAsync(bytes, shutdown.Token);
                        var message = Encoding.UTF8.GetString(bytes);
                        if (!message.StartsWith('<') || !message.Contains(" Cipherazzi ", StringComparison.Ordinal))
                            throw new InvalidDataException("Invalid RFC 5424 header.");
                        Messages.Enqueue(message);
                        if (DropNextConnectionAfterOneMessage)
                        {
                            DropNextConnectionAfterOneMessage = false;
                            client.Client.LingerState = new LingerOption(true, 0);
                            break;
                        }
                    }
                }
                catch (Exception error) when (error is IOException or
                    System.Security.Authentication.AuthenticationException
                    or OperationCanceledException or SocketException)
                {
                    if (errorLog is not null && !shutdown.IsCancellationRequested)
                        File.AppendAllText(errorLog, error + Environment.NewLine);
                }
            }
        });
    }

    public static JsonElement Envelope(string message)
    {
        using var document = JsonDocument.Parse(message[(message.IndexOf(" - {", StringComparison.Ordinal) + 3)..]);
        return document.RootElement.Clone();
    }

    public async Task Until(Func<bool> ready)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!ready())
        {
            if (reading.IsFaulted)
                await reading;
            await Task.Delay(20, timeout.Token);
        }
    }

    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel();
        listener.Stop();
        await reading;
        shutdown.Dispose();
    }
}
