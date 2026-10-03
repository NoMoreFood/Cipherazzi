using System.Text.Json;

namespace Cipherazzi.Data;

public sealed record MigrationChange(string Key, string Computer, string Application, string Peer, string Change,
    long BaselineObservations, long CurrentObservations, double? BeforePercent, double? AfterPercent);

public sealed record MigrationBaseline(int Schema, DateTimeOffset CapturedUtc, string DatabaseId, string ScopeKey,
    int WindowMinutes, List<string> ClassificationRules, List<ReadinessRow> Rows)
{
    public static MigrationBaseline Capture(PqcSnapshot snapshot, int windowMinutes) =>
        new(1, DateTimeOffset.UtcNow, snapshot.DatabaseId, snapshot.ScopeKey, windowMinutes, snapshot.RuleVersions, snapshot.Rows);

    public void Save(string path) => SaveAsync(path).GetAwaiter().GetResult();

    public async Task SaveAsync(string path, CancellationToken cancellation = default)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                65536, FileOptions.Asynchronous))
            {
                await JsonSerializer.SerializeAsync(stream, this, cancellationToken: cancellation).ConfigureAwait(false);
                if (stream.Length > 32 * 1024 * 1024)
                    throw new InvalidDataException("Baseline exceeds 32 MiB. Narrow the current scope.");
            }
            cancellation.ThrowIfCancellationRequested();
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public static MigrationBaseline Load(string path) => LoadAsync(path).GetAwaiter().GetResult();

    public static async Task<MigrationBaseline> LoadAsync(string path, CancellationToken cancellation = default)
    {
        if (new FileInfo(path).Length > 32 * 1024 * 1024)
            throw new InvalidDataException("Baseline exceeds 32 MiB.");
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            65536, FileOptions.Asynchronous);
        var baseline = await JsonSerializer.DeserializeAsync<MigrationBaseline>(stream, cancellationToken: cancellation)
            .ConfigureAwait(false) ??
            throw new InvalidDataException("The baseline is empty.");
        if (baseline.Schema != 1 || baseline.Rows is null || baseline.Rows.Count > 20000 ||
            baseline.ClassificationRules is null || baseline.ClassificationRules.Count > 128 ||
            baseline.ScopeKey is null || baseline.ScopeKey.Length > 2048 ||
            string.IsNullOrEmpty(baseline.DatabaseId) || baseline.DatabaseId.Length > 256 ||
            baseline.ClassificationRules.Any(rule => string.IsNullOrEmpty(rule) || rule.Length > 128) ||
            baseline.WindowMinutes is < 0 or > 525600 ||
            baseline.Rows.Any(row => row is null || string.IsNullOrEmpty(row.Key) || row.Key.Length > 8192 ||
                new[] { row.Computer, row.Application, row.Peer, row.Transport }.Any(value => value is null || value.Length > 2048) ||
                row.FirstUs < 0 || row.LastUs < row.FirstUs || row.LastUs > 253402300799999000 ||
                row.Counts is null || row.Counts.Count > 256 || row.Counts.Keys.Any(key => key.Length > 512) ||
                row.Total < 0 || row.Counts.Values.Any(count => count < 0 || count > row.Total)) ||
            baseline.Rows.Select(row => row.Key).Distinct(StringComparer.OrdinalIgnoreCase).Count() != baseline.Rows.Count)
            throw new InvalidDataException("The baseline format or counts are invalid.");
        return baseline;
    }

    public List<MigrationChange> Compare(PqcSnapshot current, int windowMinutes, int minimumSamples)
    {
        if (minimumSamples < 1)
            throw new ArgumentOutOfRangeException(nameof(minimumSamples));
        if (ScopeKey != current.ScopeKey || WindowMinutes != windowMinutes)
            throw new InvalidDataException("Baseline scope and time-window length must match the current view.");
        if (!ClassificationRules.SequenceEqual(current.RuleVersions))
            throw new InvalidDataException("Classification rules differ. Capture a baseline using the current classification rules.");
        var before = Rows.ToDictionary(row => row.Key, StringComparer.OrdinalIgnoreCase);
        var changes = new List<MigrationChange>();
        foreach (var row in current.Rows)
        {
            if (!before.Remove(row.Key, out var baseline))
            {
                changes.Add(new(row.Key, row.Computer, row.Application, row.Peer, "New observed cohort",
                    0, row.Total, null, null));
                continue;
            }
            void Add(string text, double? first = null, double? last = null) =>
                changes.Add(new(row.Key, row.Computer, row.Application, row.Peer, text, baseline.Total, row.Total, first, last));
            if (baseline.Total < minimumSamples || row.Total < minimumSamples)
            {
                Add("Insufficient samples for comparison");
                continue;
            }
            if (baseline.PqKeys > 0 && baseline.ClassicalKeys == 0 && row.ClassicalKeys > 0)
                Add("Classical key establishment newly observed after PQ selection");
            if (baseline.PqAuth > 0 && baseline.ClassicalAuth == 0 && row.ClassicalAuth > 0)
                Add("Classical server authentication newly observed after PQ authentication");
            foreach (var (label, first, last, threshold, decrease) in new[]
            {
                ("PQ key-selection share decreased", baseline.PqKeys, row.PqKeys, 5.0, true),
                ("Unknown server-authentication share increased", baseline.UnknownAuth, row.UnknownAuth, 10.0, false),
                ("Endpoint-reported failure share increased", baseline.Failures, row.Failures, 5.0, false)
            })
            {
                var firstPercent = first * 100.0 / baseline.Total;
                var lastPercent = last * 100.0 / row.Total;
                if ((decrease ? firstPercent - lastPercent : lastPercent - firstPercent) >= threshold)
                    Add(label, firstPercent, lastPercent);
            }
        }
        foreach (var row in before.Values)
            changes.Add(new(row.Key, row.Computer, row.Application, row.Peer, "Cohort not observed in current scope",
                row.Total, 0, null, null));
        return changes;
    }
}
