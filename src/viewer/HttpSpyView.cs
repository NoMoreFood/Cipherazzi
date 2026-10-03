using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Cipherazzi.Viewer;

// Decoded HTTP and HTTPS requests and responses from the HTTP Spy store beside the connected journal.
internal sealed class HttpSpyView : UserControl
{
    private readonly ResultGrid grid = new() { Name = "HttpSpyGrid", AccessibleName = "Decoded HTTP messages" };
    private readonly TextBox request = Pane("Request message");
    private readonly TextBox response = Pane("Response message");
    private readonly Label status = new()
    {
        Dock = DockStyle.Fill,
        AutoEllipsis = true,
        TextAlign = ContentAlignment.MiddleLeft,
        Text = "No HTTP Spy messages loaded",
        UseMnemonic = false
    };
    private readonly CommandButton previous = new() { Text = "&Newer", AutoSize = true, Enabled = false };
    private readonly CommandButton next = new() { Text = "Ol&der", AutoSize = true, Enabled = false };
    private readonly ChoiceBox payload = new()
    {
        DropDownStyle = ComboBoxStyle.DropDownList,
        AutoSize = true,
        AccessibleName = "Payload view"
    };
    private readonly CommandButton previewRequest = BodyButton("Preview image", "Preview the request image");
    private readonly CommandButton saveRequest = BodyButton("Save body…", "Save the request body to a file");
    private readonly CommandButton previewResponse = BodyButton("Preview image", "Preview the response image");
    private readonly CommandButton saveResponse = BodyButton("Save body…", "Save the response body to a file");
    private readonly ToolStripMenuItem copyUrl = new("Copy &URL") { Enabled = false };
    private readonly ToolStripMenuItem copyCurl = new("Copy as c&URL (PowerShell)") { Enabled = false };
    private readonly ToolStripMenuItem connection = new("View &TLS connection") { Enabled = false, Visible = false };
    private readonly Label metadata = new()
    {
        Dock = DockStyle.Fill, AutoEllipsis = true, UseMnemonic = false,
        TextAlign = ContentAlignment.MiddleLeft, AccessibleName = "Message connection and timings",
        Margin = new Padding(2, 0, 2, 2)
    };
    private readonly ToolTip hints = new();
    private readonly FlowLayoutPanel findBar = new()
    {
        AutoSize = true, Dock = DockStyle.Fill, Visible = false, WrapContents = false
    };
    private readonly InputTextBox find = new() { AccessibleName = "Find in message", Width = 220 };
    private TextBox? findTarget;
    private readonly List<PageCursor> pages = [PageCursor.Newest];
    private List<HttpExchangeRow> rows = [];
    private DatabaseSource? source;
    private HttpExchangeDetail? detail;
    private HttpBodyFile? requestFile, responseFile;
    private string summaryText = "", notice = "";
    internal HttpBodyFile? ResponseFile => responseFile;
    private int page;
    private int generation;
    private bool loading;
    private string context = "";
    private DateTime updated;
    private (string Identity, long Revision)? stamp;
    private string journalIdentity = "";
    private CancellationTokenSource? cancellation;
    private CancellationTokenSource? detailCancellation;
    public event Action? RefreshRequested;
    public event Action? ConnectRequested;
    public event Action? ClearFiltersRequested;
    public event Action<HttpExchangeRow>? ConnectionRequested;

    public HttpSpyView()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(3);
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        root.RowStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        var toolbar = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 5 };
        for (var column = 0; column < 4; ++column)
            toolbar.ColumnStyles.Add(new(SizeType.AutoSize));
        toolbar.ColumnStyles.Add(new(SizeType.Percent, 100));
        payload.Items.AddRange(["Automatic", "Raw text", "Hex", "Base64 decoded", "URL decoded", "SAML", "JWT"]);
        payload.SelectedIndex = 0;
        payload.Anchor = AnchorStyles.Left;
        payload.FontChanged += (_, _) => FitPayload();
        payload.DpiChangedAfterParent += (_, _) => FitPayload();
        FitPayload();
        toolbar.Controls.Add(previous, 0, 0);
        toolbar.Controls.Add(next, 1, 0);
        toolbar.Controls.Add(new Label
        {
            Text = "&Payload",
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            Margin = new Padding(12, 0, 3, 0)
        }, 2, 0);
        toolbar.Controls.Add(payload, 3, 0);
        toolbar.Controls.Add(status, 4, 0);
        root.Controls.Add(toolbar, 0, 2);
        var findNext = new CommandButton { Text = "Find next", AutoSize = true };
        var closeFind = new CommandButton { Text = "Close", AutoSize = true };
        findBar.Controls.AddRange([new Label { Text = "Find", AutoSize = true, Anchor = AnchorStyles.Left },
            find, findNext, closeFind]);
        root.Controls.Add(findBar, 0, 1);
        findNext.Click += (_, _) => FindNext();
        closeFind.Click += (_, _) => { findBar.Visible = false; findTarget?.Focus(); };
        find.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                FindNext();
            }
        };
        AnalyticsView.ConfigureGrid(grid);
        foreach (var (name, caption, width) in new[]
        {
            ("Time", "Started", 125), ("Process", "Process", 130), ("Method", "Method", 70), ("Status", "Status", 60),
            ("Host", "Host", 170), ("Path", "Path", 260), ("Type", "Content type", 120), ("Size", "Response", 80),
            ("Duration", "Time (ms)", 80), ("Protocol", "Protocol", 130), ("State", "State", 85)
        })
            grid.Columns.Add(new DataGridViewTextBoxColumn
            {
                Name = name,
                HeaderText = caption,
                Width = width,
                SortMode = DataGridViewColumnSortMode.NotSortable
            });
        foreach (var name in new[] { "Status", "Size", "Duration" })
            grid.Columns[name]!.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight;

        // The path takes the width the other columns leave, so long targets stay readable on wide windows.
        grid.Columns["Path"]!.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
        grid.Columns["Path"]!.MinimumWidth = 200;
        var menu = new ContextMenuStrip();
        menu.Items.AddRange([copyUrl, copyCurl, connection]);
        grid.ContextMenuStrip = menu;
        copyUrl.Click += (_, _) =>
        {
            if (detail is not null)
                Clipboard.SetText(detail.Row.Url);
        };
        copyCurl.Click += (_, _) =>
        {
            if (detail is not null)
            {
                Clipboard.SetText(Curl(detail));
                notice = Redacted(detail) ? "Copied with missing credentials: capture again with Keep cookies and " +
                    "credentials to replay authentication." : "Copied as cURL.";
                UpdateStatus();
            }
        };
        connection.Click += (_, _) =>
        {
            if (detail is not null)
                ConnectionRequested?.Invoke(detail.Row);
        };

        // Requests sit beside their responses beneath the message list.
        var messages = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Margin = Padding.Empty,
            Orientation = Orientation.Vertical,
            SplitterWidth = 5,
            Size = new Size(1200, 300),
            SplitterDistance = 600,
            Panel1MinSize = 120,
            Panel2MinSize = 120
        };
        messages.Panel1.Controls.Add(Titled("Request", request, previewRequest, saveRequest));
        messages.Panel2.Controls.Add(Titled("Response", response, previewResponse, saveResponse));
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 5,
            Size = new Size(1200, 600),
            SplitterDistance = 340,
            Panel1MinSize = 100,
            Panel2MinSize = 120
        };
        split.Panel1.Controls.Add(grid);
        var details = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        details.ColumnStyles.Add(new(SizeType.Percent, 100));
        details.RowStyles.Add(new(SizeType.AutoSize));
        details.RowStyles.Add(new(SizeType.Percent, 100));
        metadata.Height = Font.Height + 4;
        metadata.FontChanged += (_, _) => metadata.Height = metadata.Font.Height + 4;
        details.Controls.Add(metadata, 0, 0);
        details.Controls.Add(messages, 0, 1);
        split.Panel2.Controls.Add(details);
        void FitMessages()
        {
            var height = Math.Max(0, split.ClientSize.Height - split.SplitterWidth);
            var rowHeight = grid.Rows.Count > 0 ? grid.Rows[0].Height : grid.RowTemplate.Height;
            var first = Math.Min(height, grid.ColumnHeadersHeight + rowHeight * 3 + grid.Margin.Vertical +
                (SystemInformation.HorizontalScrollBarHeight + 4) * grid.DeviceDpi / 96);
            var last = Math.Min(height - first, metadata.Height + Math.Max(request.Font.Height, response.Font.Height) *
                6 + saveResponse.GetPreferredSize(Size.Empty).Height);
            split.Panel1MinSize = split.Panel2MinSize = 0;
            split.SplitterDistance = Math.Clamp(split.SplitterDistance, first, height - last);
            split.Panel1MinSize = first;
            split.Panel2MinSize = last;
        }
        split.Resize += (_, _) => FitMessages();
        metadata.FontChanged += (_, _) => FitMessages();
        saveResponse.FontChanged += (_, _) => FitMessages();
        grid.RowHeightChanged += (_, _) => FitMessages();
        grid.ColumnHeadersHeightChanged += (_, _) => FitMessages();
        root.Controls.Add(split, 0, 0);
        Controls.Add(root);
        grid.SetEmptyState("No HTTP Spy messages", "Connect to a capture journal recorded with HTTP Spy.",
            "Connect…", () => ConnectRequested?.Invoke());
        previous.Click += (_, _) =>
        {
            previous.Enabled = next.Enabled = false;
            if (page > 0)
                --page;
            updated = default;
            RefreshRequested?.Invoke();
        };
        next.Click += (_, _) =>
        {
            if (rows.Count == 0)
                return;
            previous.Enabled = next.Enabled = false;
            if (pages.Count > page + 1)
                pages.RemoveRange(page + 1, pages.Count - page - 1);
            pages.Add(new(rows[^1].StartedUs, rows[^1].Id));
            ++page;
            updated = default;
            RefreshRequested?.Invoke();
        };
        grid.CurrentCellChanged += (_, _) => _ = SelectionAsync();
        previewRequest.Click += (_, _) => Preview(requestFile);
        previewResponse.Click += (_, _) => Preview(responseFile);
        saveRequest.Click += async (_, _) => await ChooseAndSaveAsync(requestFile);
        saveResponse.Click += async (_, _) => await ChooseAndSaveAsync(responseFile);
        payload.SelectedIndexChanged += async (_, _) =>
        {
            if (detail is null)
                return;
            var loaded = detail;
            detailCancellation?.Cancel();
            detailCancellation?.Dispose();
            detailCancellation = new();
            try { await PresentAsync(loaded, detailCancellation.Token); }
            catch (OperationCanceledException) { }
        };
        Clear("Select a message to read its request and response.");
    }

    // The drop-down is at least as wide as its longest view name plus the arrow, at the current font and scaling.
    private void FitPayload() => payload.MinimumSize = new(payload.Items.Cast<string>()
        .Max(item => TextRenderer.MeasureText(item, payload.Font).Width) + 16 * payload.DeviceDpi / 96 +
        SystemInformation.GetVerticalScrollBarWidthForDpi(payload.DeviceDpi), 0);

    private static TextBox Pane(string name) => new()
    {
        Multiline = true,
        ReadOnly = true,
        WordWrap = false,
        ScrollBars = ScrollBars.Both,
        Dock = DockStyle.Fill,
        Font = new Font("Consolas", 9),
        AccessibleName = name,
        MaxLength = 0
    };

    private static CommandButton BodyButton(string text, string name) => new()
    {
        Text = text,
        AutoSize = true,
        Visible = false,
        AccessibleName = name,
        Margin = new Padding(6, 0, 0, 2)
    };

    private static Control Titled(string title, Control content, params CommandButton[] actions)
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Margin = Padding.Empty
        };
        panel.RowStyles.Add(new(SizeType.AutoSize));
        panel.RowStyles.Add(new(SizeType.Percent, 100));
        panel.ColumnStyles.Add(new(SizeType.Percent, 100));
        var header = new TableLayoutPanel
        {
            AutoSize = true,
            Dock = DockStyle.Fill,
            ColumnCount = actions.Length + 1,
            Margin = Padding.Empty
        };
        header.ColumnStyles.Add(new(SizeType.Percent, 100));
        header.Controls.Add(new Label
        {
            Text = title,
            AutoSize = true,
            UseMnemonic = false,
            Anchor = AnchorStyles.Left,
            Margin = new Padding(2)
        }, 0, 0);
        for (var index = 0; index < actions.Length; ++index)
        {
            header.ColumnStyles.Add(new(SizeType.AutoSize));
            header.Controls.Add(actions[index], index + 1, 0);
        }
        panel.Controls.Add(header, 0, 0);
        panel.Controls.Add(content, 0, 1);
        return panel;
    }

    private void UpdateStatus() => status.Text = summaryText + (notice.Length > 0 ? " · " + notice : "");

    // Offer to preview a picture or save a binary body only when the selected message has one.
    private void ShowBodyActions(HttpBodyFile? requested, HttpBodyFile? received)
    {
        requestFile = requested;
        responseFile = received;
        previewRequest.Visible = requested is { Image: true };
        saveRequest.Visible = requested is not null;
        previewResponse.Visible = received is { Image: true };
        saveResponse.Visible = received is not null;
        notice = "";
    }

    // Pictures are decoded by the system image codecs, so oversized ones are refused before they are expanded.
    internal static Bitmap? DecodeImage(byte[] bytes)
    {
        try
        {
            using var stream = new MemoryStream(bytes);
            using var decoded = Image.FromStream(stream, false, true);
            return decoded.Width * (long)decoded.Height > 100_000_000 ? null : new Bitmap(decoded);
        }
        catch (Exception error) when (error is ArgumentException or OutOfMemoryException or ExternalException)
        {
            return null;
        }
    }

    private void Preview(HttpBodyFile? file)
    {
        if (file is null)
            return;
        using var image = DecodeImage(file.Bytes);
        notice = image is null ? "This image cannot be previewed; save it to open it elsewhere." : "";
        UpdateStatus();
        if (image is null)
            return;
        using var dialog = new ImagePreviewDialog(image, $"{file.FileName} · {image.Width:N0} × {image.Height:N0} " +
            $"pixels · {FormatSize(file.Bytes.Length)}" + (file.Partial ? " · partial" : ""), Font);
        UiTheme.Apply(dialog);
        dialog.ShowDialog(this);
    }

    private async Task ChooseAndSaveAsync(HttpBodyFile? file)
    {
        if (file is null)
            return;
        using var dialog = new SaveFileDialog { Title = "Save body", FileName = file.FileName, Filter = "All files|*.*" };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            await SaveBodyAsync(file, dialog.FileName);
    }

    internal async Task<bool> SaveBodyAsync(HttpBodyFile file, string path)
    {
        try
        {
            await ExportFile.WriteAsync(path, (stream, token) => stream.WriteAsync(file.Bytes, token).AsTask(),
                CancellationToken.None, source);
            notice = $"Saved {FormatSize(file.Bytes.Length)} to {Path.GetFileName(path)}" +
                (file.Partial ? "; the collector kept only part of this body." : ".");
            UpdateStatus();
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
        {
            notice = "The body could not be saved. " + error.Message;
            UpdateStatus();
            return false;
        }
    }

    private void Clear(string message)
    {
        detail = null;
        metadata.Text = "";
        hints.SetToolTip(metadata, "");
        request.WordWrap = true;
        request.Text = message;
        response.Text = "";
        copyUrl.Enabled = copyCurl.Enabled = connection.Enabled = false;
        connection.Visible = false;
        ShowBodyActions(null, null);
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => bytes.ToString("N0", CultureInfo.CurrentCulture) + " B",
        < 1024 * 1024 => (bytes / 1024.0).ToString("N1", CultureInfo.CurrentCulture) + " KB",
        _ => (bytes / 1048576.0).ToString("N1", CultureInfo.CurrentCulture) + " MB"
    };

    private static bool Redacted(HttpExchangeDetail value) => value.RequestHeaders.Split("\r\n")
        .Any(line => line.IndexOf(':') is > 0 and var colon &&
            line[(colon + 1)..].TrimStart().StartsWith("[redacted", StringComparison.Ordinal));

    internal static string Curl(HttpExchangeDetail value)
    {
        // Preserve recorded arguments as PowerShell literals, including every accepted apostrophe delimiter.
        string Quote(string text) => "'" + text.Replace("'", "''")
            .Replace("\u2018", "\u2018\u2018").Replace("\u2019", "\u2019\u2019")
            .Replace("\u201a", "\u201a\u201a").Replace("\u201b", "\u201b\u201b") + "'";
        var command = new StringBuilder("curl.exe -i -X ").Append(Quote(value.Row.Method)).Append(' ')
            .Append(Quote(value.Row.Url));
        foreach (var line in value.RequestHeaders.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0 || line[(colon + 1)..].TrimStart().StartsWith("[redacted", StringComparison.Ordinal) ||
                line[..colon].Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                line[..colon].Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                continue;
            command.Append(" -H ").Append(Quote(line));
        }
        // Keep body text literal instead of interpreting a leading @ as a local filename.
        if (value.RequestBody.Length > 0)
            command.Append(" --data-raw ").Append(Quote(Encoding.UTF8.GetString(value.RequestBody)));
        return (Redacted(value) ? "# WARNING: Redacted credential headers were omitted; authentication may fail.\r\n" :
            "") + command;
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if (keyData == (Keys.Control | Keys.F) && (request.Focused || response.Focused || findBar.ContainsFocus))
        {
            findTarget = response.Focused ? response : request.Focused ? request : findTarget ?? request;
            if (findTarget.SelectionLength > 0)
                find.Text = findTarget.SelectedText;
            findBar.Visible = true;
            find.Focus();
            find.SelectAll();
            return true;
        }
        if (keyData == Keys.F3 && (request.Focused || response.Focused || findBar.ContainsFocus))
        {
            if (request.Focused || response.Focused)
                findTarget = response.Focused ? response : request;
            FindNext();
            return true;
        }
        if (keyData == Keys.Escape && findBar.Visible)
        {
            findBar.Visible = false;
            findTarget?.Focus();
            return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    private void FindNext()
    {
        var pane = findTarget ?? request;
        if (find.Text.Length == 0)
            return;
        var start = Math.Min(pane.TextLength, pane.SelectionStart + pane.SelectionLength);
        var position = pane.Text.IndexOf(find.Text, start, StringComparison.OrdinalIgnoreCase);
        if (position < 0)
            position = pane.Text.IndexOf(find.Text, StringComparison.OrdinalIgnoreCase);
        notice = position < 0 ? "Text not found in this message." : "";
        if (position >= 0)
        {
            pane.Select(position, find.Text.Length);
            pane.ScrollToCaret();
            pane.Focus();
        }
        UpdateStatus();
    }

    private async Task SelectionAsync()
    {
        detailCancellation?.Cancel();
        if (grid.CurrentRow is not { Index: >= 0 } selected || selected.Index >= rows.Count || source is null)
            return;
        var row = rows[selected.Index];
        Clear("Reading message…");
        detailCancellation?.Dispose();
        detailCancellation = new();
        var token = detailCancellation.Token;
        var selectedSource = source;
        try
        {
            await PresentAsync(await Task.Run(() => HttpSpyStore.ReadDetail(selectedSource, row.Id, token), token),
                token);
        }
        catch (OperationCanceledException) { }
        catch (Exception error) when (error is HttpSpyUnavailableException or InvalidDataException)
        {
            if (!token.IsCancellationRequested && !IsDisposed)
                Clear(error.Message);
        }
    }

    private async Task PresentAsync(HttpExchangeDetail loaded, CancellationToken token)
    {
        var view = (HttpPayloadView)Math.Max(0, payload.SelectedIndex);
        var row = loaded.Row;
        var texts = await Task.Run(() => Describe(loaded, view), token);
        (HttpBodyFile? Request, HttpBodyFile? Response) files = row.State == "encrypted" ? (null, null) :
            await Task.Run(() => (HttpMessageText.BodyFile(loaded.RequestHeaders, loaded.RequestBody,
                row.RequestBytes, row.Target), row.Status is null ? null : HttpMessageText.BodyFile(
                loaded.ResponseHeaders, loaded.ResponseBody, row.ResponseBytes, row.Target)), token);
        if (token.IsCancellationRequested || IsDisposed)
            return;
        detail = loaded;
        metadata.Text = $"Client: {row.Client}" + (row.Process.Length > 0 ? $" ({row.Process})" : "") +
            $" → Server: {row.Server} · " +
            $"Flow #{row.FlowId} (Seq {row.Sequence}) · Send: {row.SendMs:N1} ms | " +
            $"Wait (TTFB): {row.WaitMs:N1} ms | Receive: {row.ReceiveMs:N1} ms";
        hints.SetToolTip(metadata, metadata.Text + (row.ClientPath.Length > 0 ? "\r\n" + row.ClientPath : "") +
            (row.Account.Length > 0 ? "\r\nAccount: " + row.Account : ""));
        ShowBodyActions(files.Request, files.Response);
        if (summaryText.Length > 0)
            UpdateStatus();
        request.WordWrap = false;
        request.Text = texts.Request;
        response.Text = texts.Response;
        copyUrl.Enabled = copyCurl.Enabled = loaded.Row.State != "encrypted";
        connection.Enabled = row.Scheme == "https";
        connection.Visible = connection.Enabled;
    }

    private static (string Request, string Response) Describe(HttpExchangeDetail value, HttpPayloadView view)
    {
        var row = value.Row;
        if (row.State == "encrypted")
            return ($"This {row.Transport} connection to {(row.Host.Length > 0 ? row.Host : row.Server)} was not " +
                $"decoded.\r\n\r\n{value.Row.Note}\r\n\r\nClient {row.Client}\r\nServer {row.Server}", "");
        var requestText = HttpMessageText.Render($"{row.Method} {row.Target} {row.Version}",
            value.RequestHeaders, value.RequestBody, row.RequestBytes, view);
        var responseText = row.Status is null ? "(no response was observed)" : HttpMessageText.Render(
            $"{row.Version} {row.Status} {value.Reason}".TrimEnd(), value.ResponseHeaders, value.ResponseBody,
            row.ResponseBytes, view);
        var note = row.Note.Length > 0 ? $"\r\n\r\n[{row.Note}]" : "";
        return (requestText, responseText + note);
    }

    public void Reset()
    {
        ++generation;
        cancellation?.Cancel();
        detailCancellation?.Cancel();
        loading = false;
        context = "";
        updated = default;
        stamp = null;
        journalIdentity = "";
        page = 0;
        pages.Clear();
        pages.Add(PageCursor.Newest);
        rows.Clear();
        grid.Rows.Clear();
        grid.SetEmptyState("Reading HTTP Spy messages…", "Reading decoded messages from the connected journal.");
        previous.Enabled = next.Enabled = false;
        Clear("Reading HTTP Spy messages…");
    }

    public async Task RefreshAsync(DatabaseSource? connected, string search, bool force)
    {
        if (connected is null || IsDisposed)
            return;
        source = connected;
        var key = connected.CacheKey + '\0' + search;
        if (context != key)
        {
            Reset();
            context = key;
        }
        if (!force && (loading || page > 0 || DateTime.UtcNow - updated < TimeSpan.FromSeconds(2)))
            return;
        cancellation?.Cancel();
        cancellation?.Dispose();
        cancellation = new();
        var token = cancellation.Token;
        var current = ++generation;
        var cursor = pages[page];
        loading = true;
        try
        {
            var known = journalIdentity.Length > 0 && !force ? stamp : null;
            var snapshot = await Task.Run(() => HttpSpyStore.Read(connected, search, cursor, Database.PageSize, known,
                token), token);
            if (current != generation || IsDisposed)
                return;
            updated = DateTime.UtcNow;
            if (snapshot is null)
                return;
            if (journalIdentity.Length > 0 && journalIdentity != snapshot.Stamp.Identity)
            {
                // A replacement store has independent message identities and pagination boundaries.
                Reset();
                context = key;
                loading = false;
                await RefreshAsync(connected, search, true);
                return;
            }
            var selected = grid.CurrentRow is { Index: >= 0 } selection && selection.Index < rows.Count ?
                rows[selection.Index].Id : (long?)null;
            var first = grid.FirstDisplayedScrollingRowIndex;
            var firstId = first > 0 && first < rows.Count ? rows[first].Id : (long?)null;
            rows = snapshot.Rows;
            stamp = snapshot.Stamp;
            journalIdentity = snapshot.Stamp.Identity;
            grid.Rows.Clear();
            foreach (var row in rows)
                grid.Rows.Add(DateTimeOffset.FromUnixTimeMilliseconds(row.StartedUs / 1000).ToLocalTime()
                    .ToString("MM-dd HH:mm:ss.fff", CultureInfo.CurrentCulture), row.Process,
                    row.State == "encrypted" ? "TLS" : row.Method,
                    row.Status?.ToString(CultureInfo.CurrentCulture) ?? "",
                    row.Host.Length > 0 ? row.Host : row.Server,
                    row.State == "encrypted" ? "Not decoded: " + row.Note : row.Target, row.ContentType,
                    row.Status is null ? "" : FormatSize(row.ResponseBytes),
                    row.State is "pending" or "encrypted" ? "" :
                        row.DurationMs.ToString("N1", CultureInfo.CurrentCulture),
                    row.Version.Length > 0 ? row.Version + " · " + row.Transport : row.Transport,
                    row.State switch
                    {
                        "complete" => "Complete",
                        "pending" => "No response",
                        "partial" => "Partial",
                        "encrypted" => "Encrypted",
                        _ => row.State
                    });
            if (selected is not null && rows.FindIndex(row => row.Id == selected) is >= 0 and var index)
                grid.CurrentCell = grid.Rows[index].Cells[0];
            if (firstId is not null && rows.FindIndex(row => row.Id == firstId) is >= 0 and var visible)
                grid.FirstDisplayedScrollingRowIndex = visible;
            previous.Enabled = page > 0;
            next.Enabled = snapshot.HasMore;
            var summary = snapshot.Summary;
            summaryText = $"{rows.Count:N0} messages · page {page + 1}" + (summary is null ? "" :
                $" · Decoded {summary.Decoded:N0} of {summary.TlsConnections:N0} HTTPS connections" +
                (summary.WithoutSecrets > 0 ? $" · {summary.WithoutSecrets:N0} without logged secrets" : "") +
                (summary.Unsupported + summary.Failed > 0 ?
                    $" · {summary.Unsupported + summary.Failed:N0} not decodable" : "") +
                " · Contains decrypted traffic");
            UpdateStatus();
            grid.SetEmptyState("No matching HTTP Spy messages",
                "Clear the search filter. The collector records messages while it runs with --httpspy.",
                "Clear search", () => ClearFiltersRequested?.Invoke());
            if (rows.Count == 0)
                Clear("No matching HTTP Spy messages.");
            else
                _ = SelectionAsync();
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            if (current == generation && !IsDisposed)
            {
                updated = DateTime.UtcNow;
                stamp = null;
                rows.Clear();
                grid.Rows.Clear();
                previous.Enabled = next.Enabled = false;

                // Keep the list's explanation short; the message pane carries the details.
                var denied = error is HttpSpyUnavailableException { Denied: true };
                var absent = error is HttpSpyUnavailableException { Denied: false };
                status.Text = denied ? "HTTP Spy messages need administrator rights." :
                    absent ? "No HTTP Spy messages for this journal." : "HTTP Spy messages are unavailable.";
                Clear(error.Message);
                if (absent)
                    grid.SetEmptyState("No HTTP Spy messages", "This journal has no decoded HTTP or HTTPS traffic.");
                else
                    grid.SetEmptyState(denied ? "Administrator rights are needed" : "HTTP Spy messages are unavailable",
                        denied ? "Start the viewer as an administrator to read decrypted traffic." :
                            "Refresh to try again.", "Refresh", () => RefreshRequested?.Invoke());
            }
        }
        finally
        {
            if (current == generation)
                loading = false;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            hints.Dispose();
            cancellation?.Cancel();
            cancellation?.Dispose();
            cancellation = null;
            detailCancellation?.Cancel();
            detailCancellation?.Dispose();
            detailCancellation = null;
        }
        base.Dispose(disposing);
    }

    public void Pause()
    {
        ++generation;
        cancellation?.Cancel();
        loading = false;
        status.Text = "Viewer updates: paused";
    }
}
