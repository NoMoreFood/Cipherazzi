using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class MigrationFeatures
{
    public static void Run(string[] args)
    {
        var source = args[0] is "sqlserver" or "postgresql" ?
            DatabaseSource.FromEnvironment(args[0], "CIPHERAZZI_CONNECTION") : DatabaseSource.Sqlite(args[0]);
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var checks = new List<string>();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var query = new Query("", "", false, PageCursor.Newest);
        var policy = new CryptoPolicy { Name = "Migration", Computer = "LAB-*", Process = "client.exe",
            ServerName = "case-*.migration.test", RequirePeerVerification = true };
        var authPolicy = new CryptoPolicy { Name = "Authentication", RequirePostQuantumKeyExchange = false,
            RequireStandardizedPqGroup = false, RequireEndpointCompletion = false,
            RequirePostQuantumServerAuthentication = true, RequirePostQuantumCertificateSignatures = true };
        var snapshot = PqcInsights.Read(source, query, 0, long.MaxValue, "Client application", [policy, authPolicy], deadline.Token);
        void Check(bool condition, string text)
        {
            if (!condition)
                throw new InvalidOperationException(text);
            checks.Add(text);
        }
        ReadinessRow Row(int number) => snapshot.Rows.Single(row => row.Peer == $"case-{number}.migration.test:443");
        Check(snapshot.Rows.Count == 10 && snapshot.Total > 0, "All ten evidence scenarios are represented without dropped observations");
        Check(Row(0).PqKeys == 0 && Row(0).ClassicalKeys == Row(0).Total && Row(0).UnknownAuth == Row(0).Total,
            "Classical key selection does not invent encrypted authentication evidence");
        Check(Row(1).PqKeys == Row(1).Total && Row(1).PqAuth == Row(1).Total && Row(1).Complete == Row(1).Total,
            "Confirmed hybrid/PQ evidence is counted independently");
        Check(Row(2).PqKeys == Row(2).Total && Row(2).ClassicalAuth == Row(2).Total,
            "Hybrid key establishment retains classical authentication");
        Check(Row(3).Failures == Row(3).Total && Row(4).UnknownKeys == Row(4).Total && Row(4).UnknownAuth == Row(4).Total,
            "Failed and unsupported handshakes remain explicit");
        Check(Row(5).UnknownKeys == Row(5).Total && Row(5).UnknownAuth == Row(5).Total,
            "PSK selection does not imply PQ provenance");
        Check(Row(6).Count("Completion", "Conflicting") == Row(6).Total && Row(6).Complete == 0,
            "Conflicting reports do not count as successful completion");
        Check(Row(7).PqAuth == Row(7).Total && Row(7).Count("Client authentication", "Post-quantum") == Row(7).Total &&
            Row(7).Count("Presented server-chain signatures", "Mixed classical/PQ") == Row(7).Total,
            "Server-side reporter roles and mixed certificate chains retain their meaning");
        Check(Row(8).ClassicalAuth == Row(8).Total && Row(9).UnknownKeys == Row(9).Total,
            "Visible TLS 1.2 signature and incomplete hello evidence classify correctly");
        var migration = snapshot.Policies.Single(result => result.Name == "Migration");
        Check(migration.Pass == Row(1).Total + Row(2).Total + Row(7).Total && migration.Insufficient > 0 && migration.Violations > 0,
            "Scoped policies distinguish passing, violated, and insufficient evidence");
        Check(snapshot.Rows.All(row => row.Counts.Values.All(count => count <= row.Total)),
            "Overlapping policies do not corrupt readiness denominators");
        var scoped = policy.Clone();
        scoped.ProcessRole = PolicyEndpoint.Server;
        var excluded = PqcInsights.Read(source, query, 0, long.MaxValue, "Collector computer", [scoped], deadline.Token);
        Check(excluded.Policies.Single().Applicable == 0 && excluded.Rows.Sum(row => row.Count("Process attribution", "Attributed")) == snapshot.Total,
            "Process-side scope and host attribution are evaluated correctly");
        var baseline = MigrationBaseline.Capture(snapshot, 0);
        baseline.Save(Path.Combine(output, "baseline.json"));
        var loaded = MigrationBaseline.Load(Path.Combine(output, "baseline.json"));
        Check(loaded.Compare(snapshot, 0, 5).Count == 0, "Baseline round-trip preserves the complete evidence scope");
        var altered = JsonSerializer.Deserialize<PqcSnapshot>(JsonSerializer.Serialize(snapshot))!;
        var changed = altered.Rows.Single(row => row.Peer == "case-1.migration.test:443");
        changed.Counts["Key establishment: Hybrid post-quantum"] = 0;
        changed.Counts["Key establishment: Classical"] = changed.Total;
        Check(loaded.Compare(altered, 0, 1).Any(change => change.Change.Contains("Classical key establishment")),
            "Baseline comparison flags newly observed classical selection");
        Check(loaded.Compare(altered, 0, int.MaxValue).All(change => change.Change == "Insufficient samples for comparison"),
            "Baseline comparison respects the minimum sample count");
        var inventory = CertificateInventory.Read(source, "", "All certificates", "", deadline.Token);
        foreach (var certificate in inventory.Rows)
        {
            var der = CertificateInventory.ReadDer(source, certificate.Sha256, deadline.Token);
            Check(der.Length > 0, "Public DER fingerprint verified: " + certificate.Sha256[..12]);
        }
        var linked = inventory.Rows.Where(row => row.Observations > 0).ToList();
        Check(linked.Count == 2 && linked.All(row => row.FirstUs is not null && row.LastUs >= row.FirstUs),
            "Certificate inventory deduplicates linked observations and derives observation times");
        Check(linked.All(row => row.Applications == 2 && row.Computers == 1),
            "Certificate inventory counts both local process identities without counting chain positions as transactions");
        Check(CertificateInventory.ReadUses(source, linked[0].Sha256, deadline.Token).All(use =>
            use.ClientApplication == "C:/Lab/client.exe" && use.ServerApplication == "C:/Lab/server.exe"),
            "Certificate usage retains both process identities and chain roles");
        Check(CertificateInventory.Read(source, "case-1.migration.test", "All certificates", "", deadline.Token).Rows.Count == 1,
            "Certificate search follows negotiation links");
        Check(CertificateInventory.Read(source, "", "PQ public key", "", deadline.Token).Rows.All(row => row.KeyClass == "Post-quantum"),
            "Certificate classification filters use catalog metadata");
        Check(CertificateInventory.Read(source, "'_%not-a-certificate", "All certificates", "", deadline.Token).Rows.Count == 0,
            "Certificate searches treat SQL wildcard punctuation as literal text");
        Check(PqcInsights.Read(source, query with { Protocol = "TLS 1.2" }, 0, long.MaxValue,
            "Client application", [], deadline.Token).Total == Row(8).Total,
            "Readiness protocol filtering retains the correct observed denominator");
        Check(PqcInsights.Read(source, query with { Incomplete = true }, 0, long.MaxValue,
            "Client application", [], deadline.Token).Total == Row(9).Total,
            "Incomplete-only readiness does not classify an unselected group");
        Check(PqcInsights.Read(source, query with { Search = "case-7.migration.test" }, 0, long.MaxValue,
            "Client application", [], deadline.Token).Rows.Single().Transport == "QUIC",
            "Scoped readiness preserves QUIC transport independently of TLS classification");
        var approved = new CryptoPolicy { Name = "Approved algorithms", ServerName = "case-2.migration.test",
            AllowedGroups = "0x11EC", AllowedServerSignatures = "0x0804", RequireCertificateEvidence = true,
            AllowedCertificateKeys = linked.Single(row => row.KeyClass == "Classical").Properties
                .Single(item => item.Name == "Public Key OID").Value };
        PqcSnapshot Evaluate(CryptoPolicy candidate) => PqcInsights.Read(source, query, 0, long.MaxValue,
            "Client application", [candidate], deadline.Token);
        Check(Evaluate(approved).Policies.Single().Pass == Row(2).Total,
            "Approved group, signature, and certificate OID rules accept matching observed algorithms");
        approved.AllowedGroups = "29";
        Check(Evaluate(approved).Policies.Single().Violations == Row(2).Total,
            "Observed selections outside an approved group list are violations");
        var roles = new CryptoPolicy { Name = "Mutual authentication", ServerName = "case-7.migration.test",
            RequirePostQuantumClientAuthentication = true, RequireCertificateEvidence = true,
            CertificateRole = PolicyCertificateRole.Both };
        Check(Evaluate(roles).Policies.Single().Insufficient == Row(7).Total,
            "Both certificate roles require evidence for each role even when client handshake authentication is confirmed");
        var analytic = Insights.ReadAnalytics(source, query with { Protocol = "TLS 1.2" }, 0, "Protocol", 20, deadline.Token);
        Check(analytic.Total == Row(8).Total, "Analytics scope filtering preserves its observation count");
        var quicPage = Database.Read(source, query with { Search = "QUIC" }, deadline.Token);
        Check(quicPage.Rows.Count == Math.Min(query.PageSize, Row(7).Total) &&
            quicPage.Rows.All(row => row.Value("Transport") == "QUIC"),
            "Connection searches match projected transport metadata without changing pagination");
        var hybridPage = Database.Read(source, query with { Search = "hybrid post-quantum" }, deadline.Token);
        Check(hybridPage.Rows.Count > 0 && hybridPage.Rows.All(row => row.Value("GroupClass") == "Hybrid post-quantum"),
            "Connection searches match JSON classifications with provider-consistent casing");
        try { loaded.Compare(snapshot with { ScopeKey = "another scope" }, 0, 5); throw new Exception("Scope accepted"); }
        catch (InvalidDataException) { checks.Add("Baseline comparisons reject different observation scopes"); }
        try { loaded.Compare(snapshot with { RuleVersions = ["another rule"] }, 0, 5); throw new Exception("Rules accepted"); }
        catch (InvalidDataException) { checks.Add("Baseline comparisons reject changed classification rules"); }
        var invalid = Path.Combine(output, "invalid-baseline.json");
        File.WriteAllText(invalid, JsonSerializer.Serialize(loaded with { Rows = [null!] }));
        try { _ = MigrationBaseline.Load(invalid); throw new Exception("Null cohort accepted"); }
        catch (InvalidDataException) { checks.Add("Malformed baseline cohorts fail with a clear validation error"); }
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        {
            provider = source.Provider.ToString(), observations = snapshot.Total, checks
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"Migration features: {checks.Count} checks passed for {source.Provider}; {snapshot.Total:N0} observations.");
    }
}
