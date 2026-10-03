using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Cipherazzi.Viewer;

internal sealed class CertificatesView : InvestigationView
{
    private readonly ChoiceBox filter = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = true };
    private readonly ResultGrid grid = new() { Name = "CertificatesGrid", AccessibleName = "Unique certificate inventory" };
    private readonly ResultGrid uses = new() { Name = "CertificateUsesGrid", AccessibleName = "Certificate negotiation usage" };
    private readonly PropertyInspector details = new();
    private readonly CommandButton export = new()
    {
        Text = "&Export certificate…", AutoSize = true, Enabled = false, Visible = false
    };
    private readonly CommandButton inspect = new()
    {
        Text = "&Windows certificate viewer…", AutoSize = true, Enabled = false, Visible = false
    };
    private readonly CommandButton previous = new() { Text = "&Previous", AutoSize = true, Enabled = false };
    private readonly CommandButton next = new() { Text = "&Next", AutoSize = true, Enabled = false };
    private readonly Label usageStatus = new() { AutoSize = true, Dock = DockStyle.Fill, UseMnemonic = false };
    private readonly List<string> pages = [""];
    private CancellationTokenSource? detailCancellation;
    private int page;
    private bool applying;
    private string selectedKey = "";
    private List<CertificateRow> rows = [];
    protected override string ScopeKey => filter.Text;

    public CertificatesView(ViewerSettings settings) : base(settings)
    {
        filter.Items.AddRange(CertificateInventory.Filters);
        filter.SelectedIndex = 0;
        filter.AccessibleName = "Certificate inventory filter";
        var tools = Toolbar();
        tools.Controls.Add(Choice("&Filter", filter));
        tools.Controls.Add(export);
        tools.Controls.Add(inspect);
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        root.ColumnStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.RowStyles.Add(new(SizeType.Percent, 100));
        root.RowStyles.Add(new(SizeType.AutoSize));
        root.Controls.Add(tools, 0, 0);
        foreach (var table in new[] { grid, uses })
            AnalyticsView.ConfigureGrid(table);
        foreach (var column in new[]
        {
            Column("Subject", "Subject", 300), Column("Issuer", "Issuer", 250), Column("Key", "Public key", 160),
            Column("KeyClass", "Key classification", 150), Column("Signature", "Certificate signature", 200),
            Column("SignatureClass", "Signature classification", 175), Column("Expires", "Expires", 185),
            Column("First", "First observed", 185), Column("Last", "Last observed", 185),
            Column("Observations", "Observations", 125, true), Column("Computers", "Computers", 110, true),
            Column("Applications", "Applications", 120, true), Column("Reuse", "SPKI reuse", 110, true),
            Column("Sha256", "SHA-256", 420)
        })
            grid.Columns.Add(column);
        grid.Columns["Expires"]!.DisplayIndex = 1;
        foreach (var name in new[] { "SignatureClass", "First", "Last", "Computers", "Applications", "Reuse",
            "Sha256" })
            grid.Columns[name]!.Visible = false;
        foreach (var column in new[]
        {
            Column("Computer", "Computer", 145), Column("Client", "Client application", 240),
            Column("Server", "Server application", 240), Column("Peer", "Server name / address", 230),
            Column("Role", "Role", 80), Column("Position", "Chain position", 135, true),
            Column("Observations", "Observations", 125, true), Column("First", "First observed", 185),
            Column("Last", "Last observed", 185)
        })
            uses.Columns.Add(column);
        ConfigureColumns(grid);
        ConfigureColumns(uses);
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal,
            SplitterWidth = 5, Size = new Size(1200, 600), SplitterDistance = 330, Panel1MinSize = 100, Panel2MinSize = 120 };
        split.Panel1.Controls.Add(grid);
        var views = new WorkspaceTabs { Dock = DockStyle.Fill };
        var properties = new TabPage("Certificate properties");
        properties.Controls.Add(details);
        views.TabPages.Add(properties);
        var usage = new TabPage("Negotiation usage");
        var usageRoot = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        usageRoot.ColumnStyles.Add(new(SizeType.Percent, 100));
        usageRoot.RowStyles.Add(new(SizeType.AutoSize));
        usageRoot.RowStyles.Add(new(SizeType.Percent, 100));
        usageRoot.Controls.Add(usageStatus, 0, 0);
        usageRoot.Controls.Add(uses, 0, 1);
        usage.Controls.Add(usageRoot);
        views.TabPages.Add(usage);
        split.Panel2.Controls.Add(views);
        root.Controls.Add(split, 0, 1);
        var footer = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 3 };
        footer.ColumnStyles.Add(new(SizeType.AutoSize));
        footer.ColumnStyles.Add(new(SizeType.AutoSize));
        footer.ColumnStyles.Add(new(SizeType.Percent, 100));
        footer.Controls.Add(previous, 0, 0);
        footer.Controls.Add(next, 1, 0);
        footer.Controls.Add(Status, 2, 0);
        root.Controls.Add(footer, 0, 2);
        Controls.Add(root);
        grid.SetEmptyState("No certificate evidence loaded", "Connect to a capture with observed public certificates.",
            "Connect…", Connect);
        uses.SetEmptyState("Select a certificate", "Its observed negotiation usage will appear here.");
        details.Clear("Select a certificate to inspect metadata and negotiation usage.");
        filter.SelectedIndexChanged += (_, _) => { Reset(); RequestRefresh(); };
        void Metrics() => filter.Width = filter.Items.Cast<object>().Max(item =>
            TextRenderer.MeasureText(item.ToString(), filter.Font).Width) + 32 * filter.DeviceDpi / 96;
        filter.FontChanged += (_, _) => Metrics();
        filter.DpiChangedAfterParent += (_, _) => Metrics();
        Metrics();
        previous.Click += (_, _) => { if (page > 0) --page; RequestRefresh(); };
        next.Click += (_, _) =>
        {
            if (rows.Count == 0)
                return;
            if (pages.Count > page + 1)
                pages.RemoveRange(page + 1, pages.Count - page - 1);
            pages.Add(rows[^1].Sha256);
            ++page;
            RequestRefresh();
        };
        grid.CurrentCellChanged += async (_, _) => await TrackAsync(SelectionAsync());
        export.Click += async (_, _) => await TrackAsync(ExportAsync(false));
        inspect.Click += async (_, _) => await TrackAsync(ExportAsync(true));
        grid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && e.ColumnIndex >= 0)
                inspect.PerformClick();
        };
        uses.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0 && uses.Rows[e.RowIndex].Tag is CertificateUse use)
                Filter(use.Peer);
        };
        var menu = new ContextMenuStrip();
        var copy = menu.Items.Add("Copy &fingerprint");
        copy.Click += (_, _) => { if (Selected is { } row) Clipboard.SetText(row.Sha256); };
        menu.Opening += (_, e) => e.Cancel = Selected is null;
        grid.ContextMenuStrip = menu;
    }

    private CertificateRow? Selected => grid.CurrentRow?.Tag as CertificateRow;

    protected override Func<CancellationToken, object> PrepareRead(DatabaseSource source, Query query)
    {
        var selectedFilter = filter.Text;
        var after = pages[page];
        var size = Settings.PageSize;
        return token => CertificateInventory.Read(source, query.Search, selectedFilter, after, token, size);
    }

    protected override void ApplyResult(object result)
    {
        var inventory = (CertificatePage)result;
        var selected = Selected?.Sha256;
        selectedKey = "";
        applying = true;
        rows = inventory.Rows;
        grid.Rows.Clear();
        foreach (var row in rows)
        {
            var index = grid.Rows.Add(row.Subject, row.Issuer, row.PublicKey, row.KeyClass, row.Signature,
                row.SignatureClass, CertificateInventory.At(row.NotAfterUs), CertificateInventory.At(row.FirstUs),
                CertificateInventory.At(row.LastUs), row.Observations, row.Computers, row.Applications, row.KeyReuse, row.Sha256);
            grid.Rows[index].Tag = row;
            if (row.Sha256 == selected)
                grid.CurrentCell = FirstVisibleCell(grid.Rows[index]);
        }
        applying = false;
        previous.Enabled = page > 0;
        next.Enabled = inventory.HasMore;
        Status.Text = $"{rows.Count:N0} unique certificates · page {page + 1} · Usage covers retained linked negotiations.";
        grid.SetEmptyState("No matching certificates",
            "Clear the search and certificate filter. Encrypted handshakes may require endpoint certificate evidence.",
            "Clear filters", () => { filter.SelectedIndex = 0; ClearFilters(); });
        _ = TrackAsync(SelectionAsync());
    }

    private async Task SelectionAsync()
    {
        if (applying)
            return;
        var row = Selected;
        export.Enabled = inspect.Enabled = row is not null;
        export.Visible = inspect.Visible = row is not null;
        if (row is null || Source is null)
        {
            detailCancellation?.Cancel();
            selectedKey = "";
            uses.Rows.Clear();
            details.Clear("Select a certificate to inspect metadata and negotiation usage.");
            usageStatus.Text = "Select a certificate to inspect negotiation usage.";
            return;
        }
        details.Show(row.Sha256, row.Subject + " · " + row.PublicKey, row.Properties, summary:
            $"Expires: {CertificateInventory.At(row.NotAfterUs)}\n" +
            $"Public key: {row.PublicKey} ({row.KeyClass}) · Certificate signature: {row.Signature}\n" +
            $"Observed in {row.Observations:N0} negotiations · Endpoint trust is assessed separately");
        var key = string.Join('\0', row.Sha256, row.Observations, row.LastUs, row.Computers, row.Applications);
        if (selectedKey == key)
            return;
        selectedKey = key;
        detailCancellation?.Cancel();
        detailCancellation?.Dispose();
        detailCancellation = CancellationTokenSource.CreateLinkedTokenSource(ClosingToken);
        var token = detailCancellation.Token;
        var source = Source;
        uses.Rows.Clear();
        usageStatus.Text = "Loading certificate usage…";
        try
        {
            var result = await Task.Run(() => CertificateInventory.ReadUses(source, row.Sha256, token), token);
            if (IsDisposed || token.IsCancellationRequested || Source != source || Selected?.Sha256 != row.Sha256)
                return;
            foreach (var use in result)
            {
                var index = uses.Rows.Add(use.Computer, use.ClientApplication, use.ServerApplication, use.Peer, use.Role,
                    use.ChainIndex + 1, use.Observations, CertificateInventory.At(use.FirstUs), CertificateInventory.At(use.LastUs));
                uses.Rows[index].Tag = use;
            }
            usageStatus.Text = $"{result.Count:N0} usage groups shown (maximum 250). Chain position 1 is the leaf.";
        }
        catch (OperationCanceledException) {}
        catch (Exception error)
        {
            if (!IsDisposed && selectedKey == key && !token.IsCancellationRequested)
                usageStatus.Text = "Usage unavailable. " + error.Message;
        }
    }

    private async Task ExportAsync(bool nativeViewer)
    {
        if (Selected is not { } row || Source is not { } source)
            return;
        string? path = null;
        var pem = false;
        if (!nativeViewer)
        {
            using var dialog = new SaveFileDialog { Filter = "Certificate DER (*.cer)|*.cer|Certificate PEM (*.pem)|*.pem",
                FileName = row.Sha256[..Math.Min(16, row.Sha256.Length)] + ".cer" };
            if (dialog.ShowDialog(this) != DialogResult.OK)
                return;
            path = dialog.FileName;
            pem = dialog.FilterIndex == 2;
        }
        export.Enabled = inspect.Enabled = false;
        Status.Text = "Loading public certificate data…";
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ClosingToken);
        cancellation.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            var der = await Task.Run(() => CertificateInventory.ReadDer(source, row.Sha256, cancellation.Token), cancellation.Token);
            if (IsDisposed || Source != source || cancellation.IsCancellationRequested)
                return;
            if (nativeViewer)
            {
                using var certificate = X509CertificateLoader.LoadCertificate(der);
                X509Certificate2UI.DisplayCertificate(certificate, Handle);
            }
            else if (pem)
                await File.WriteAllTextAsync(path!, PemEncoding.WriteString("CERTIFICATE", der), Encoding.ASCII, cancellation.Token);
            else
                await File.WriteAllBytesAsync(path!, der, cancellation.Token);
            if (!IsDisposed && Source == source)
                Status.Text = nativeViewer ? "Public certificate opened." : "Public certificate exported.";
        }
        catch (OperationCanceledException) {}
        catch (Exception error)
        {
            if (!IsDisposed && Source == source)
                Status.Text = "Certificate operation failed. " + error.Message;
        }
        finally
        {
            if (!IsDisposed)
                export.Enabled = inspect.Enabled = Selected is not null;
        }
    }

    public override void Reset()
    {
        page = 0;
        pages.Clear();
        pages.Add("");
        base.Reset();
    }

    public override void Pause()
    {
        detailCancellation?.Cancel();
        selectedKey = "";
        base.Pause();
    }

    protected override void ClearResult()
    {
        detailCancellation?.Cancel();
        selectedKey = "";
        rows = [];
        applying = true;
        grid.Rows.Clear();
        applying = false;
        uses.Rows.Clear();
        usageStatus.Text = "Select a certificate to inspect negotiation usage.";
        export.Enabled = inspect.Enabled = previous.Enabled = next.Enabled = false;
        export.Visible = inspect.Visible = false;
        details.Clear("Select a certificate to inspect metadata and negotiation usage.");
        grid.SetEmptyState(Source is null ? "No certificate evidence loaded" : "Loading certificates…",
            "Connect to a capture with observed public certificates.", Source is null ? "Connect…" : "",
            Source is null ? Connect : null);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            detailCancellation?.Cancel();
            detailCancellation?.Dispose();
            detailCancellation = null;
        }
        base.Dispose(disposing);
    }
}
