using System.Diagnostics;
using System.Text.Json;
using Cipherazzi.Data;

SQLitePCL.Batteries_V2.Init();
if (args[0] == "--query-costs")
{
    QueryCosts.Run(args[1], args[2]);
    return;
}
var source = args[0] is "sqlserver" or "postgresql" ?
    DatabaseSource.FromEnvironment(args[0], "CIPHERAZZI_CONNECTION") : DatabaseSource.Sqlite(args[0]);
var output = Path.GetFullPath(args[1]);
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
var measurements = new List<object>();
var query = new Query("", "", false, PageCursor.Newest);
using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(15));

// Measure complete user workflows, including connection opening, parsing, and allocation.
void Measure(string name, Action action, int repetitions = 9)
{
    var samples = new List<double>();
    var cold = Stopwatch.StartNew();
    action();
    var coldMs = cold.Elapsed.TotalMilliseconds;
    action();
    GC.Collect();
    GC.WaitForPendingFinalizers();
    var allocated = GC.GetTotalAllocatedBytes(precise: true);
    var cpu = Process.GetCurrentProcess().TotalProcessorTime;
    for (var iteration = 0; iteration < repetitions; ++iteration)
    {
        var watch = Stopwatch.StartNew();
        action();
        samples.Add(watch.Elapsed.TotalMilliseconds);
    }
    samples.Sort();
    measurements.Add(new
    {
        name, first_ms = coldMs, median_ms = samples[samples.Count / 2], maximum_ms = samples[^1],
        allocated_bytes_per_call = (GC.GetTotalAllocatedBytes(precise: true) - allocated) / repetitions,
        cpu_ms_per_call = (Process.GetCurrentProcess().TotalProcessorTime - cpu).TotalMilliseconds / repetitions,
        working_set_bytes = Environment.WorkingSet, samples_ms = samples
    });
    Console.WriteLine($"{name}: {samples[samples.Count / 2]:N2} ms; first {coldMs:N2} ms");
}
if (!args.Contains("--features-only"))
{
    Measure("connections_250", () => Database.Read(source, query, deadline.Token));
    Measure("connections_2000", () => Database.Read(source, query with { PageSize = 2000 }, deadline.Token));
    var revision = Database.Read(source, query, deadline.Token).Revision;
    Measure("unchanged_live_poll", () => Database.ReadIfChanged(source, query, deadline.Token, revision));
    Measure("investigation_revision_poll", () => Database.ReadStamp(source, deadline.Token));
    Measure("filtered_missing", () => Database.Read(source,
        query with { Search = "missing-profile-audit.example" }, deadline.Token), 5);
    foreach (var dimension in new[] { "Protocol", "Group classification", "Client process" })
        Measure("analytics_" + dimension, () => Insights.ReadAnalytics(source, query, 0, dimension, 20, deadline.Token), 5);
}
if (args.Contains("--features"))
{
    Measure("readiness", () => PqcInsights.Read(source, query, 0, long.MaxValue,
        "Client application", [new CryptoPolicy()], deadline.Token), 5);
    Measure("readiness_three_policies", () => PqcInsights.Read(source, query, 0, long.MaxValue,
        "Client application", [new CryptoPolicy(), new CryptoPolicy { Name = "Authentication",
            RequirePostQuantumServerAuthentication = true }, new CryptoPolicy { Name = "Certificates",
            RequirePostQuantumCertificateSignatures = true }], deadline.Token), 5);
    Measure("certificate_inventory", () => CertificateInventory.Read(source, "", "All certificates", "", deadline.Token), 5);
}
File.WriteAllText(output, JsonSerializer.Serialize(new
{
    provider = source.Provider.ToString(), measurements
}, new JsonSerializerOptions { WriteIndented = true }));
