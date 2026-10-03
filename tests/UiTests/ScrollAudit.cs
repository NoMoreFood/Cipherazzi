using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Cipherazzi.Data;
using Cipherazzi.Viewer;

namespace Cipherazzi.UiTests;

internal static class ScrollAudit
{
    private const int MouseWheel = 0x020A;

    [DllImport("user32.dll")]
    private static extern nint SendMessage(nint window, int message, nint wParam, nint lParam);

    [DllImport("user32.dll")]
    private static extern uint GetGuiResources(nint process, uint flags);

    public static int Run(string[] args)
    {
        var output = Path.GetFullPath(args[1]);
        Directory.CreateDirectory(output);
        var settings = ViewerSettings.Load(Path.GetFullPath("viewer/Cipherazzi.Viewer.config"));
        settings.Theme = "Light";
        settings.AnalyticsMinutes = 0;
        var measurements = new List<object>();
        var errors = new List<string>();
        Application.ThreadException += (_, e) => errors.Add(e.Exception.ToString());
        using var runner = new Form { ShowInTaskbar = false, StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000) };
        using var window = new MainForm(DatabaseSource.Sqlite(args[0]), null, settings)
        {
            ShowInTaskbar = false, StartPosition = FormStartPosition.Manual,
            Location = new Point(-20000, -20000)
        };
        var exit = 0;
        window.Shown += async (_, _) =>
        {
            try
            {
                var controls = Descendants(window).ToList();
                var grid = controls.OfType<DataGridView>().Single(control => control.Name == "ConnectionsGrid");
                var refresh = controls.OfType<Button>().Single(control => control.Text == "&Refresh");
                var live = controls.OfType<CheckBox>().Single(control => control.Text == "&Live");
                var details = controls.OfType<PropertyInspector>().Single(control =>
                    control.AccessibleName == "Selected observation details");
                await Until(() => grid.RowCount == settings.PageSize && refresh.Enabled);
                live.Checked = false;
                var valueRequests = 0;
                grid.CellValueNeeded += (_, _) => ++valueRequests;

                // Send native wheel messages and render the actual viewport without bitmap allocation per frame.
                var desktop = Screen.FromControl(window).WorkingArea;
                var frame = window.Size - window.ClientSize;
                var sizes = new[] { new Size(1000, 650), new Size(1600, 1000), window.ClientSize,
                    new Size(desktop.Width - frame.Width, desktop.Height - frame.Height) }.Distinct().ToArray();
                foreach (var size in sizes)
                {
                    window.ClientSize = size;
                    window.PerformLayout();
                    foreach (var theme in new[] { "Light", "Dark" })
                    {
                        settings.Theme = theme;
                        UiTheme.Apply(window, theme);
                        await Task.Delay(100);
                        using var bitmap = new Bitmap(grid.Width, grid.Height);
                        var point = grid.PointToScreen(new Point(grid.Width / 2, grid.Height / 2));
                        var coordinates = (nint)((uint)(ushort)point.X | ((uint)(ushort)point.Y << 16));
                        var dispatch = new List<double>();
                        var paint = new List<double>();
                        var redraw = new List<double>();
                        var reference = new List<double>();
                        var redrawRequests = 0;
                        grid.CurrentCell = grid.Rows[5].Cells["Sni"];
                        var selected = grid.CurrentRow!.Cells["Sni"].Value?.ToString();
                        grid.FirstDisplayedScrollingRowIndex = 0;
                        var table = (ResultGrid)grid;
                        using (var native = new Bitmap(grid.Width, grid.Height))
                        {
                            table.CacheCellRendering = false;
                            grid.DrawToBitmap(native, grid.ClientRectangle);
                            table.CacheCellRendering = true;
                            var cold = Stopwatch.StartNew();
                            grid.DrawToBitmap(bitmap, grid.ClientRectangle);
                            var coldMs = cold.Elapsed.TotalMilliseconds;
                            if (!SamePixels(native, bitmap))
                            {
                                native.Save(Path.Combine(output, "native.png"));
                                bitmap.Save(Path.Combine(output, "cached.png"));
                                throw new InvalidOperationException("Cached cells changed native rendering pixels.");
                            }
                            measurements.Add(new { scenario = "first_cached_render", theme,
                                client_size = size.ToString(), elapsed_ms = coldMs });
                        }
                        grid.DrawToBitmap(bitmap, grid.ClientRectangle);
                        var allocated = GC.GetTotalAllocatedBytes(precise: true);
                        var requests = valueRequests;
                        for (var index = 0; index < 80; ++index)
                        {
                            var direction = index < 40 ? -120 : 120;
                            var watch = Stopwatch.StartNew();
                            SendMessage(grid.Handle, MouseWheel, (nint)(direction << 16), coordinates);
                            dispatch.Add(watch.Elapsed.TotalMilliseconds);
                            watch.Restart();
                            var requestsBeforeRedraw = valueRequests;
                            grid.Update();
                            redraw.Add(watch.Elapsed.TotalMilliseconds);
                            redrawRequests += valueRequests - requestsBeforeRedraw;
                            watch.Restart();
                            grid.DrawToBitmap(bitmap, grid.ClientRectangle);
                            paint.Add(watch.Elapsed.TotalMilliseconds);
                            if (index % 4 == 0)
                            {
                                table.CacheCellRendering = false;
                                watch.Restart();
                                grid.DrawToBitmap(bitmap, grid.ClientRectangle);
                                reference.Add(watch.Elapsed.TotalMilliseconds);
                                table.CacheCellRendering = true;
                            }
                            if (index == 39 && grid.FirstDisplayedScrollingRowIndex <= 0)
                                throw new InvalidOperationException("Wheel messages did not scroll the table.");
                            await Task.Delay(1);
                        }
                        if (selected != grid.CurrentRow?.Cells["Sni"].Value?.ToString())
                            throw new InvalidOperationException("Wheel scrolling changed the selected observation.");
                        dispatch.Sort();
                        paint.Sort();
                        redraw.Sort();
                        reference.Sort();
                        measurements.Add(new
                        {
                            scenario = "native_wheel_and_viewport_render", theme, client_size = size.ToString(),
                            viewport_size = grid.Size.ToString(), window.DeviceDpi, rows = grid.RowCount,
                            dispatch_median_ms = dispatch[40], dispatch_p95_ms = dispatch[76],
                            render_median_ms = paint[40], render_p95_ms = paint[76], render_max_ms = paint[^1],
                            native_redraw_median_ms = redraw[40], native_redraw_p95_ms = redraw[76],
                            native_redraw_cell_requests_per_frame = redrawRequests / 80,
                            reference_render_median_ms = reference[10], reference_render_samples = reference.Count,
                            allocated_bytes_per_frame = (GC.GetTotalAllocatedBytes(precise: true) - allocated) / 80,
                            cell_value_requests_per_frame = (valueRequests - requests) / 80,
                            selection_preserved = true, native_pixels_preserved = true,
                            cached_cell_bytes = table.CachedCellBytes, cached_cell_count = table.CachedCellCount
                        });
                        Console.WriteLine($"{theme} {size}: render {paint[40]:N2} ms, wheel {dispatch[40]:N2} ms");
                    }
                }

                // Measure row navigation separately from wheel painting and include the property inspector work.
                var selection = new List<double>();
                for (var index = 1; index <= 60; ++index)
                {
                    var watch = Stopwatch.StartNew();
                    grid.CurrentCell = grid.Rows[index].Cells["Sni"];
                    selection.Add(watch.Elapsed.TotalMilliseconds);
                    await Task.Delay(35);
                }
                await Until(() => details.Summary.StartsWith(grid.CurrentRow!.Cells["Sni"].Value!.ToString()!));
                selection.Sort();
                measurements.Add(new { scenario = "row_navigation", median_ms = selection[30],
                    p95_ms = selection[57], maximum_ms = selection[^1] });

                var snapshot = await Task.Run(() => Database.Read(args[0], new Query("", "", false,
                    PageCursor.Newest, 50), CancellationToken.None));
                var inspectors = new List<object>();
                foreach (var row in snapshot.Rows.Take(20))
                {
                    var watch = Stopwatch.StartNew();
                    var properties = row.Properties;
                    var prepare = watch.Elapsed.TotalMilliseconds;
                    watch.Restart();
                    details.Show("audit-" + row.Id, row.Sni, properties);
                    inspectors.Add(new { row.Sni, properties = properties.Count,
                        categories = properties.Select(value => value.Category).Distinct().Count(),
                        prepare_ms = prepare, display_ms = watch.Elapsed.TotalMilliseconds });
                }
                measurements.Add(new { scenario = "inspector_by_evidence", rows = inspectors });

                // Exercise live refresh while scrolling so the journal poll cannot reset the viewport.
                var liveFrames = new List<double>();
                live.Checked = true;
                using (var bitmap = new Bitmap(grid.Width, grid.Height))
                {
                    for (var index = 0; index < 90; ++index)
                    {
                        var target = 10 + index % 70;
                        grid.FirstDisplayedScrollingRowIndex = target;
                        var watch = Stopwatch.StartNew();
                        grid.DrawToBitmap(bitmap, grid.ClientRectangle);
                        liveFrames.Add(watch.Elapsed.TotalMilliseconds);
                        await Task.Delay(80);
                        if (grid.FirstDisplayedScrollingRowIndex != target)
                            throw new InvalidOperationException("An unchanged journal moved the scroll position.");
                    }
                }
                live.Checked = false;
                liveFrames.Sort();
                measurements.Add(new { scenario = "scroll_during_live_poll", median_ms = liveFrames[45],
                    p95_ms = liveFrames[85], maximum_ms = liveFrames[^1], scroll_preserved = true });

                // Compare native pixels after changing text size, focus, selection, and partially visible columns.
                var renderingChecks = 0;
                foreach (var points in new[] { 9f, 12f })
                {
                    window.Font = new Font("Segoe UI", points);
                    foreach (var theme in new[] { "Light", "Dark" })
                    {
                        settings.Theme = theme;
                        UiTheme.Apply(window, theme);
                        grid.Focus();
                        grid.CurrentCell = grid.Rows[37].Cells["Sni"];
                        foreach (var offset in new[] { 0, 145, 650 })
                        {
                            grid.HorizontalScrollingOffset = offset;
                            VerifyPixels((ResultGrid)grid, output);
                            ++renderingChecks;
                        }
                    }
                }
                measurements.Add(new { scenario = "native_rendering_after_font_theme_focus_and_clipping_changes",
                    frames = renderingChecks, native_pixels_preserved = true });

                // Exercise both cache limits with unique cells, then verify deterministic disposal of bitmap resources.
                using var process = Process.GetCurrentProcess();
                var resourcesBefore = GetGuiResources(process.Handle, 0);
                var cacheLimits = new List<object>();
                foreach (var width in new[] { 180, 1300 })
                {
                    using var scratch = new ResultGrid
                    {
                        Size = new Size(1600, 360), ReadOnly = true, RowHeadersVisible = false,
                        AllowUserToAddRows = false, VirtualMode = true, RowTemplate = { Height = 32 }
                    };
                    window.Controls.Add(scratch);
                    scratch.BringToFront();
                    for (var index = 0; index < (width == 180 ? 8 : 1); ++index)
                        scratch.Columns.Add(new DataGridViewTextBoxColumn { Width = width,
                            CellTemplate = new ResultGrid.TextCell() });
                    scratch.CellValueNeeded += (_, e) => e.Value = $"Unique {e.RowIndex} / {e.ColumnIndex} Ω 中";
                    scratch.RowCount = 1200;
                    UiTheme.Apply(scratch);
                    using var bitmap = new Bitmap(scratch.Width, scratch.Height);
                    var samples = new List<double>();
                    long peakBytes = 0;
                    var peakCount = 0;
                    for (var index = 0; index < 900; index += 10)
                    {
                        scratch.FirstDisplayedScrollingRowIndex = index;
                        var watch = Stopwatch.StartNew();
                        scratch.DrawToBitmap(bitmap, scratch.ClientRectangle);
                        samples.Add(watch.Elapsed.TotalMilliseconds);
                        peakBytes = Math.Max(peakBytes, scratch.CachedCellBytes);
                        peakCount = Math.Max(peakCount, scratch.CachedCellCount);
                        if (scratch.CachedCellBytes > 16 * 1024 * 1024 || scratch.CachedCellCount > 512)
                            throw new InvalidOperationException("Scrolling exceeded the cell cache budget.");
                    }
                    VerifyPixels(scratch, output);
                    scratch.Dispose();
                    if (scratch.CachedCellBytes != 0 || scratch.CachedCellCount != 0)
                        throw new InvalidOperationException("Disposed grid retained cached cell images.");
                    samples.Sort();
                    cacheLimits.Add(new { column_width = width, peak_bytes = peakBytes, peak_cells = peakCount,
                        unique_scroll_render_median_ms = samples[samples.Count / 2],
                        unique_scroll_render_p95_ms = samples[(int)(samples.Count * .95)],
                        released_on_dispose = true });
                }
                var resourcesAfter = GetGuiResources(process.Handle, 0);
                if (resourcesAfter > resourcesBefore + 10)
                    throw new InvalidOperationException("Scrolling retained excessive GDI resources after disposal.");
                measurements.Add(new { scenario = "cache_limits_and_resource_disposal", limits = cacheLimits,
                    gdi_before = resourcesBefore, gdi_after = resourcesAfter });
            }
            catch (Exception error)
            {
                errors.Add(error.ToString());
                exit = 1;
            }
            finally
            {
                window.Close();
                await Until(() => window.IsDisposed);
                File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new
                {
                    result = errors.Count == 0 ? "passed" : "failed",
                    terminal_server_session = SystemInformation.TerminalServerSession,
                    measurements, errors
                }, new JsonSerializerOptions { WriteIndented = true }));
                runner.Close();
            }
        };
        runner.Shown += (_, _) => window.Show(runner);
        Application.Run(runner);
        return exit;
    }

    private static IEnumerable<Control> Descendants(Control parent)
    {
        foreach (Control child in parent.Controls)
        {
            yield return child;
            foreach (var descendant in Descendants(child))
                yield return descendant;
        }
    }

    private static bool SamePixels(Bitmap first, Bitmap second)
    {
        var bounds = new Rectangle(Point.Empty, first.Size);
        var original = first.LockBits(bounds, System.Drawing.Imaging.ImageLockMode.ReadOnly,
            System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        var cached = second.LockBits(bounds, System.Drawing.Imaging.ImageLockMode.ReadOnly,
            System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        try
        {
            var left = new byte[original.Stride * original.Height];
            var right = new byte[cached.Stride * cached.Height];
            Marshal.Copy(original.Scan0, left, 0, left.Length);
            Marshal.Copy(cached.Scan0, right, 0, right.Length);
            return left.AsSpan().SequenceEqual(right);
        }
        finally
        {
            first.UnlockBits(original);
            second.UnlockBits(cached);
        }
    }

    private static void VerifyPixels(ResultGrid table, string output)
    {
        using var native = new Bitmap(table.Width, table.Height);
        using var cached = new Bitmap(table.Width, table.Height);
        table.CacheCellRendering = false;
        table.DrawToBitmap(native, table.ClientRectangle);
        table.CacheCellRendering = true;
        table.DrawToBitmap(cached, table.ClientRectangle);
        if (SamePixels(native, cached))
            return;
        native.Save(Path.Combine(output, "native.png"));
        cached.Save(Path.Combine(output, "cached.png"));
        throw new InvalidOperationException("Cached cells changed native rendering pixels.");
    }

    private static async Task Until(Func<bool> ready)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.ElapsedMilliseconds > 15000)
                throw new TimeoutException("Scrolling workflow did not complete.");
            await Task.Delay(20);
        }
    }
}
