namespace Cipherazzi.Viewer;

// Shows a picture from a message body at its own size when it fits, and scaled down to fit otherwise.
internal sealed class ImagePreviewDialog : Form
{
    private readonly PictureBox picture = new()
    {
        Dock = DockStyle.Fill,
        Margin = Padding.Empty,
        AccessibleName = "Image preview"
    };

    public Size ImageSize => picture.Image?.Size ?? Size.Empty;

    public ImagePreviewDialog(Image image, string caption, Font font)
    {
        Text = caption;
        Font = font;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        ClientSize = new Size(640, 480);
        MinimumSize = new Size(360, 260);
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false;
        ShowInTaskbar = false;
        Padding = new Padding(12);
        picture.Image = image.Clone() as Image;
        var close = new CommandButton
        {
            Text = "Close",
            AutoSize = true,
            DialogResult = DialogResult.Cancel,
            Anchor = AnchorStyles.Right,
            Margin = new Padding(0, 8, 0, 0)
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(picture, 0, 0);
        layout.Controls.Add(close, 0, 1);
        Controls.Add(layout);
        CancelButton = close;
        picture.Resize += (_, _) => Fit();
        Fit();
    }

    // Small pictures stay at their own size instead of being blown up.
    private void Fit()
    {
        if (picture.Image is { } image)
            picture.SizeMode = image.Width <= picture.ClientSize.Width && image.Height <= picture.ClientSize.Height ?
                PictureBoxSizeMode.CenterImage : PictureBoxSizeMode.Zoom;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            picture.Image?.Dispose();
        base.Dispose(disposing);
    }
}
