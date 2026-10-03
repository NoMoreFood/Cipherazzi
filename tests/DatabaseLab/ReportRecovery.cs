using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Cipherazzi.Data;
using Microsoft.Data.Sqlite;

internal static class ReportRecovery
{
    private sealed class ProgressCallback(Action<long> action) : IProgress<long>
    {
        public void Report(long value) => action(value);
    }

    public static void Run(string[] args)
    {
        var seed = Path.GetFullPath(args[0]);
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var cases = new List<object>();
        var failures = 0;
        var query = new Query("", "", false, PageCursor.Newest);
        string Hash(string path)
        {
            using var input = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(input));
        }
        string Journal(string name)
        {
            var path = Path.Combine(output, name);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var original = (SqliteConnection)DatabaseSource.Sqlite(seed).CreateConnection();
            using var copy = new SqliteConnection($"Data Source={path};Pooling=False");
            original.Open();
            copy.Open();
            original.BackupDatabase(copy);
            return path;
        }
        void Check(string name, bool passed, object details)
        {
            cases.Add(new { name, passed, details });
            if (!passed)
                ++failures;
        }

        // A directory alias must not bypass the guard against replacing the source journal with its report.
        var aliasRoot = Path.Combine(Path.GetTempPath(), "cipherazzi-report-" + Guid.NewGuid().ToString("N"));
        var alias = Path.Combine(aliasRoot, "alias");
        Exception? failure = null;
        try
        {
            var aliased = Journal(Path.Combine(aliasRoot, "actual", "journal.csv"));
            if (OperatingSystem.IsWindows())
            {
                var start = new ProcessStartInfo("powershell.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true
                };
                foreach (var value in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                    "New-Item -ItemType Junction -ErrorAction Stop -Path '" + alias.Replace("'", "''") +
                    "' -Target '" + Path.GetDirectoryName(aliased)!.Replace("'", "''") + "' | Out-Null" })
                    start.ArgumentList.Add(value);
                using var process = Process.Start(start)!;
                if (!process.WaitForExit(10000))
                {
                    process.Kill(entireProcessTree: true);
                    throw new TimeoutException("Creating the test directory alias timed out.");
                }
                if (process.ExitCode != 0)
                    throw new IOException(
                        "Creating the test directory alias failed. " + process.StandardError.ReadToEnd());
            }
            else
                Directory.CreateSymbolicLink(alias, Path.GetDirectoryName(aliased)!);
            var before = Hash(aliased);
            try
            {
                ReportExport.Write(DatabaseSource.Sqlite(Path.Combine(alias, "journal.csv")), query,
                    ReportKind.Connections, aliased, [], CancellationToken.None);
            }
            catch (Exception error) { failure = error; }
            Check("Aliased source journal remains a database", failure is ArgumentException && Hash(aliased) == before,
                new { rejected = failure is ArgumentException, unchanged = Hash(aliased) == before,
                    error = failure?.GetType().Name, message = failure?.Message });

        }
        finally
        {
            // Unlink the alias before removing only this run's verified temporary fixture.
            var temporaryRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
            if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(aliasRoot)), temporaryRoot,
                StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The export fixture escaped its temporary directory.");
            if (Directory.Exists(alias))
                Directory.Delete(alias);
            if (Directory.Exists(aliasRoot))
                Directory.Delete(aliasRoot, recursive: true);
        }

        // Existing database destinations are protected, including one created after export has already started.
        var sourcePath = Journal("source.db");
        var source = DatabaseSource.Sqlite(sourcePath);
        foreach (var during in new[] { false, true })
        {
            var target = Path.Combine(output, $"database-{during}.csv");
            string expected;
            if (during)
            {
                File.WriteAllText(target, "Existing report");
                expected = "";
            }
            else
                expected = Hash(Journal(Path.GetFileName(target)));
            var replaced = false;
            failure = null;
            try
            {
                ReportExport.Write(source, query, ReportKind.Connections, target, [], CancellationToken.None,
                    new ProgressCallback(_ =>
                    {
                        if (!during || replaced)
                            return;
                        File.Copy(seed, target, overwrite: true);
                        expected = Hash(target);
                        replaced = true;
                    }));
            }
            catch (Exception error) { failure = error; }
            Check("Database destination preserved; changed during export=" + during,
                failure is ArgumentException && Hash(target) == expected && (!during || replaced),
                new { rejected = failure is ArgumentException, unchanged = Hash(target) == expected,
                    replaced_during_export = replaced, error = failure?.GetType().Name });
        }

        // Baselines and public certificates share the same database and atomic-publication protections.
        var baseline = MigrationBaseline.Capture(PqcInsights.Read(source, query, 0, long.MaxValue,
            "Client application", [], CancellationToken.None), 0);
        var certificate = CertificateInventory.Read(source, "", "All certificates", "", CancellationToken.None)
            .Rows.First();
        var der = CertificateInventory.ReadDer(source, certificate.Sha256, CancellationToken.None);
        foreach (var kind in new[] { "baseline.json", "certificate.cer", "certificate.pem" })
        {
            var contents = kind.EndsWith(".pem", StringComparison.Ordinal) ? System.Text.Encoding.ASCII.GetBytes(
                System.Security.Cryptography.PemEncoding.WriteString("CERTIFICATE", der)) : der;
            Task Export(string path, CancellationToken cancellation) => kind == "baseline.json" ?
                baseline.SaveAsync(path, cancellation) : ExportFile.WriteAsync(path,
                    (stream, token) => stream.WriteAsync(contents, token).AsTask(), cancellation, source);
            var target = Journal(kind);
            var before = Hash(target);
            failure = null;
            try { Export(target, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (Exception error) { failure = error; }
            Check(kind + " preserves an existing database", failure is ArgumentException && Hash(target) == before,
                new { rejected = failure is ArgumentException, unchanged = Hash(target) == before });
            var ordinary = Path.Combine(output, "ordinary-" + kind);
            File.WriteAllText(ordinary, "Existing export");
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            failure = null;
            try { Export(ordinary, cancellation.Token).GetAwaiter().GetResult(); }
            catch (Exception error) { failure = error; }
            Check(kind + " cancellation preserves existing output", failure is OperationCanceledException &&
                File.ReadAllText(ordinary) == "Existing export", new { error = failure?.GetType().Name });
            Export(ordinary, CancellationToken.None).GetAwaiter().GetResult();
            Check(kind + " replaces ordinary output", kind == "baseline.json" ?
                MigrationBaseline.Load(ordinary).Rows.Count == baseline.Rows.Count :
                File.ReadAllBytes(ordinary).SequenceEqual(contents), new { bytes = new FileInfo(ordinary).Length });
        }
        var changing = Path.Combine(output, "changing-certificate.cer");
        File.WriteAllText(changing, "Existing export");
        failure = null;
        try
        {
            ExportFile.WriteAsync(changing, async (stream, token) =>
            {
                await stream.WriteAsync(der, token);
                File.Copy(seed, changing, overwrite: true);
            }, CancellationToken.None, source).GetAwaiter().GetResult();
        }
        catch (Exception error) { failure = error; }
        Check("A database appearing during staged export is preserved", failure is ArgumentException &&
            Hash(changing) == Hash(seed), new { error = failure?.GetType().Name });

        // Cancellation and a sharing violation preserve a prior report and remove all staged output.
        var cancelled = Path.Combine(output, "cancelled.jsonl");
        File.WriteAllText(cancelled, "Existing report");
        using (var cancellation = new CancellationTokenSource())
        {
            failure = null;
            try
            {
                ReportExport.Write(source, query, ReportKind.Connections, cancelled, [], cancellation.Token,
                    new ProgressCallback(_ => cancellation.Cancel()));
            }
            catch (Exception error) { failure = error; }
            Check("Cancelled export preserves its destination", failure is OperationCanceledException &&
                File.ReadAllText(cancelled) == "Existing report", new { error = failure?.GetType().Name });
        }
        var locked = Path.Combine(output, "locked.csv");
        File.WriteAllText(locked, "Existing report");
        using (var blocker = new FileStream(locked, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            failure = null;
            try { ReportExport.Write(source, query, ReportKind.Connections, locked, [], CancellationToken.None); }
            catch (Exception error) { failure = error; }
            Check("Locked destination preserves its original bytes", failure is IOException or
                UnauthorizedAccessException &&
                File.ReadAllText(locked) == "Existing report", new { error = failure?.GetType().Name });
        }
        var shortFile = Path.Combine(output, "short.csv");
        File.WriteAllText(shortFile, "old");
        var rows = ReportExport.Write(source, query, ReportKind.Connections, shortFile, [], CancellationToken.None);
        Check("A short ordinary report can be replaced", rows >= 1000 && File.ReadLines(shortFile).Count() > rows,
            new { rows });
        var staged = Directory.EnumerateFiles(output, "*.tmp", SearchOption.AllDirectories).ToArray();
        Check("Failed exports remove staging files", staged.Length == 0, new { files = staged });
        File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
        { passed = failures == 0, cases }, new JsonSerializerOptions { WriteIndented = true }));
        if (failures != 0)
            throw new InvalidOperationException($"{failures} export recovery checks failed.");
        Console.WriteLine($"Export recovery: {cases.Count} checks passed.");
    }
}
