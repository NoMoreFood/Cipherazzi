using System.ComponentModel;

namespace Cipherazzi.Viewer;

internal sealed class PropertyInspector : UserControl
{
    private sealed class CertificateButton : CommandButton
    {
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            // Draw the open glyph independently of text padding at the native category row height.
            var side = Math.Min(Width, Height) - 6 * DeviceDpi / 96f;
            if (side <= 0)
                return;
            var scale = side / 16;
            var left = (Width - side) / 2;
            var top = (Height - side) / 2;
            PointF At(float x, float y) => new(left + x * scale, top + y * scale);
            e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using var pen = new Pen(Enabled ? ForeColor : UiTheme.Muted, Math.Max(1, DeviceDpi / 96f));
            e.Graphics.DrawLines(pen, [At(11, 7), At(11, 14), At(2, 14), At(2, 5), At(7, 5)]);
            e.Graphics.DrawLine(pen, At(6, 10), At(14, 2));
            e.Graphics.DrawLines(pen, [At(9, 2), At(14, 2), At(14, 7)]);
        }
    }

    private sealed class Values(List<ObservationProperty> values) : CustomTypeDescriptor
    {
        private readonly PropertyDescriptorCollection properties =
            new(values.Select((item, index) => new Field(item, index)).ToArray(), readOnly: true);

        public override object GetPropertyOwner(PropertyDescriptor? descriptor) => this;
        public override PropertyDescriptorCollection GetProperties() => properties;
        public override PropertyDescriptorCollection GetProperties(Attribute[]? attributes) => properties;
    }

    private sealed class Field(ObservationProperty item, int index) :
        PropertyDescriptor(index.ToString(), [new CategoryAttribute(item.Category),
            new DisplayNameAttribute(item.Name), new DescriptionAttribute(item.Evidence)])
    {
        public override Type ComponentType => typeof(Values);
        public override string Category => item.Category;
        public override string DisplayName => item.Name;
        public override string Description => item.Evidence;
        public override Type PropertyType => typeof(string);
        public override bool IsReadOnly => true;
        public override bool CanResetValue(object component) => false;
        public override object GetValue(object? component) => item.Value;
        public override void ResetValue(object component) {}
        public override void SetValue(object? component, object? value) {}
        public override bool ShouldSerializeValue(object component) => false;
    }

    private readonly PropertyGrid grid = new()
    {
        Dock = DockStyle.Fill, PropertySort = PropertySort.Categorized, ToolbarVisible = false,
        HelpVisible = true, AccessibleName = "Selected observation properties"
    };
    private readonly Label caption = new()
    {
        Dock = DockStyle.Top, AutoEllipsis = true, Height = 24, Padding = new Padding(4, 0, 4, 0),
        TextAlign = ContentAlignment.MiddleLeft, UseMnemonic = false
    };
    private readonly Label overview = new()
    {
        Dock = DockStyle.Top, AutoEllipsis = true, Visible = false, UseMnemonic = false,
        Padding = new Padding(4, 2, 4, 4), TextAlign = ContentAlignment.TopLeft, AccessibleName = "Evidence overview"
    };
    private readonly Control viewport;
    private readonly ToolTip hints = new();
    private readonly Dictionary<string, CommandButton> certificateButtons = [];
    private readonly Dictionary<string, AccessibleObject> certificateHeaders = [];
    private string identity = "";
    private List<ObservationProperty> values = [];
    private bool certificateBusy;
    public string Summary => caption.Text;
    public PropertyGrid Grid => grid;
    public event Action<string>? CertificateRequested;
    [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool CertificateBusy
    {
        get => certificateBusy;
        set
        {
            certificateBusy = value;
            foreach (var button in certificateButtons.Values)
                button.Enabled = !value;
        }
    }

    public PropertyInspector()
    {
        Dock = DockStyle.Fill;
        Controls.Add(grid);
        Controls.Add(overview);
        Controls.Add(caption);
        viewport = grid.Controls.Cast<Control>().Single(child => child.AccessibilityObject.Role == AccessibleRole.Table);
        viewport.Paint += (_, _) => PositionCertificateButtons();
        viewport.Layout += (_, _) => PositionCertificateButtons();
        grid.SelectedGridItemChanged += (_, _) => PositionCertificateButtons();
        var menu = new ContextMenuStrip();
        var copy = menu.Items.Add("Copy &value");
        copy.Click += (_, _) =>
        {
            if (grid.SelectedGridItem?.Value is string value)
                Clipboard.SetText(value);
        };
        var all = menu.Items.Add("Copy &all properties");
        all.Click += (_, _) => Clipboard.SetText(string.Join(Environment.NewLine,
            values.Select(item => $"{item.Category} / {item.Name}: {item.Value}")));
        menu.Items.Add(new ToolStripSeparator());
        var expand = menu.Items.Add("&Expand all");
        expand.Click += (_, _) =>
        {
            grid.ExpandAllGridItems();
            PositionCertificateButtons();
        };
        var collapse = menu.Items.Add("&Collapse all");
        collapse.Click += (_, _) =>
        {
            grid.CollapseAllGridItems();
            PositionCertificateButtons();
        };
        menu.Opening += (_, e) =>
        {
            copy.Visible = grid.SelectedGridItem?.Value is string { Length: > 0 };
            all.Visible = values.Count > 0;
            expand.Enabled = collapse.Enabled = values.Count > 0;
            e.Cancel = !copy.Visible && !all.Visible;
        };
        grid.ContextMenuStrip = menu;
        FontChanged += (_, _) => UpdateTextMetrics();
        DpiChangedAfterParent += (_, _) => UpdateTextMetrics();
        SizeChanged += (_, _) => grid.HelpVisible = Height >= Font.Height * 13;
    }

    private void UpdateTextMetrics()
    {
        caption.Height = Font.Height + 6 * DeviceDpi / 96;
        overview.Height = Font.Height * Math.Clamp(overview.Text.Count(character => character == '\n') + 1, 1, 3) +
            6 * DeviceDpi / 96;
    }

    public void Show(string key, string title, List<ObservationProperty> properties, string[]? certificates = null,
        string summary = "")
    {
        caption.Text = title;
        overview.Text = summary;
        overview.AccessibleDescription = summary;
        overview.Visible = summary.Length > 0;
        hints.SetToolTip(overview, summary);
        UpdateTextMetrics();
        UpdateCertificateButtons(properties, certificates ?? []);
        if (identity == key && values.SequenceEqual(properties))
            return;
        var selected = grid.SelectedGridItem?.Label;
        var selectedCategory = grid.SelectedGridItem?.Parent?.Label;
        var same = identity == key;
        var expanded = new HashSet<string>();
        GridItem? root = grid.SelectedGridItem;
        while (root?.Parent is { } parent)
            root = parent;
        if (identity == key && root is not null)
            foreach (GridItem category in root.GridItems)
                if (category.Expanded)
                    expanded.Add(category.Label ?? "");
        identity = key;
        values = properties;
        grid.SelectedObject = properties.Count == 0 ? null : new Values(properties);
        root = grid.SelectedGridItem;
        while (root?.Parent is { } parent)
            root = parent;
        if (root is not null)
        {
            foreach (GridItem category in root.GridItems)
            {
                category.Expanded = same ? expanded.Contains(category.Label ?? "") :
                    category.Label is "Connection" or "Server selection" or "PQC evidence" or "Endpoint evidence" or
                        "SSH negotiation" or "VPN evidence" or "OpenVPN control TLS" or
                        "Raw classification" or "Raw endpoint" or
                        "Cohort" or "Key establishment" or "Server authentication" or "Certificate" or "Inventory" or "Policy";
                foreach (GridItem item in category.GridItems)
                    if (item.Label == selected && category.Label == selectedCategory)
                        grid.SelectedGridItem = item;
            }
        }
        PositionCertificateButtons();
    }

    private void UpdateCertificateButtons(List<ObservationProperty> properties, string[] certificates)
    {
        if (certificateButtons.Count == 0 && certificates.Length == 0)
            return;

        // Only linked, unambiguous certificates offer a native viewer action.
        var categories = properties.Select(item => item.Category).ToHashSet();
        var hashes = new Dictionary<string, string>();
        foreach (var reference in certificates.Take(64))
        {
            var parts = reference.Split('|', 2);
            if (parts.Length != 2 || parts[1].Length == 0 || !categories.Contains(parts[0] + " certificate"))
                continue;
            var category = parts[0] + " certificate";
            if (!hashes.TryAdd(category, parts[1]) &&
                !hashes[category].Equals(parts[1], StringComparison.OrdinalIgnoreCase))
                hashes[category] = "";
        }
        foreach (var category in certificateButtons.Keys.ToArray())
        {
            if (hashes.GetValueOrDefault(category) is { Length: > 0 })
                continue;
            var button = certificateButtons[category];
            hints.SetToolTip(button, null);
            button.Dispose();
            certificateButtons.Remove(category);
            certificateHeaders.Remove(category);
        }
        foreach (var (category, hash) in hashes)
        {
            if (hash.Length == 0)
                continue;
            if (!certificateButtons.TryGetValue(category, out var button))
            {
                button = new CertificateButton
                {
                    Visible = false, AccessibleName = "Open " + category,
                    AccessibleDescription = "Open this certificate in the Windows certificate viewer."
                };
                button.FlatAppearance.BorderSize = 0;
                button.Click += (_, _) =>
                {
                    if (button.Tag is string fingerprint)
                        CertificateRequested?.Invoke(fingerprint);
                };
                certificateButtons.Add(category, button);
                Controls.Add(button);
                hints.SetToolTip(button, "Open " + category + " in Windows certificate viewer");
                UiTheme.Apply(button);
                button.BringToFront();
            }
            button.Tag = hash;
            button.Enabled = !certificateBusy;
        }
    }

    private void PositionCertificateButtons()
    {
        if (certificateButtons.Count == 0 || !viewport.IsHandleCreated)
            return;

        // Use current public accessibility bounds so actions follow native category expansion and scrolling.
        certificateHeaders.Clear();
        var accessible = viewport.AccessibilityObject;
        var count = accessible.GetChildCount();
        for (var index = 0; index < count && certificateHeaders.Count < certificateButtons.Count; ++index)
            if (accessible.GetChild(index) is { Role: AccessibleRole.ButtonDropDownGrid, Name: { } name } header &&
                certificateButtons.ContainsKey(name))
                certificateHeaders[name] = header;
        var visible = RectangleToClient(viewport.RectangleToScreen(viewport.ClientRectangle));
        foreach (var (category, button) in certificateButtons)
        {
            var bounds = certificateHeaders.TryGetValue(category, out var header) ?
                RectangleToClient(header.Bounds) : Rectangle.Empty;
            button.Visible = bounds.Height >= viewport.Font.Height && visible.Contains(bounds);
            if (!button.Visible)
                continue;
            var side = bounds.Height - 2;
            button.Bounds = new Rectangle(bounds.Right - side - 2, bounds.Top + 1, side, side);
        }
    }

    public void Clear(string message) => Show("", message, []);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            hints.Dispose();
        base.Dispose(disposing);
    }
}
