using System.ComponentModel;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Runtime.InteropServices;

namespace Cipherazzi.Viewer;

internal sealed class ResultGrid : DataGridView
{
    private const long CacheBudget = 16 * 1024 * 1024;
    private readonly record struct CellImageKey(string Text, string Font, float FontSize, FontStyle FontStyle,
        GraphicsUnit FontUnit, byte CharacterSet, bool VerticalFont, Size Size, float DpiX, float DpiY,
        Color BackColor, Color ForeColor, Color SelectionBackColor, Color SelectionForeColor, Color GridColor,
        Padding Padding, DataGridViewContentAlignment Alignment, DataGridViewTriState Wrap, RightToLeft Direction,
        DataGridViewElementStates State, TextRenderingHint Hint, int Contrast, DataGridViewAdvancedCellBorderStyle Top,
        DataGridViewAdvancedCellBorderStyle Bottom, DataGridViewAdvancedCellBorderStyle Left,
        DataGridViewAdvancedCellBorderStyle Right);
    private sealed record CellImage(CellImageKey Key, Bitmap Bitmap, Graphics Surface, nint Context,
        long Bytes) : IDisposable
    {
        public void Dispose()
        {
            Surface.ReleaseHdc(Context);
            Surface.Dispose();
            Bitmap.Dispose();
        }
    }
    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern bool BitBlt(nint destination, int x, int y, int width, int height,
        nint source, int sourceX, int sourceY, uint operation);
    private readonly Dictionary<CellImageKey, LinkedListNode<CellImage>> images = [];
    private readonly LinkedList<CellImage> recent = [];
    private readonly List<(nint Context, Rectangle Visible, Point Origin)> copies = [];
    private long cachedBytes;
    private readonly EmptyState empty = new() { Visible = false };
    private bool hasEmptyState;
    private bool copyPixels;
    private (float DpiX, float DpiY, TextRenderingHint Hint, int Contrast) paintSettings;
    private Font? cachedFont;
    private string cachedFontName = "";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    internal bool CacheCellRendering { get; set; } = true;
    internal long CachedCellBytes => cachedBytes;
    internal int CachedCellCount => images.Count;

    public ResultGrid()
    {
        DoubleBuffered = true;
        Controls.Add(empty);
    }

    public void SetEmptyState(string title, string message, string actionText = "", Action? action = null)
    {
        hasEmptyState = true;
        empty.Set(title, message, actionText, action);
        empty.Visible = RowCount == 0;
        empty.BringToFront();
    }

    protected override void OnRowsAdded(DataGridViewRowsAddedEventArgs e)
    {
        base.OnRowsAdded(e);
        if (hasEmptyState)
            empty.Visible = RowCount == 0;
    }

    protected override void OnRowsRemoved(DataGridViewRowsRemovedEventArgs e)
    {
        base.OnRowsRemoved(e);
        if (hasEmptyState)
        {
            empty.Visible = RowCount == 0;
            empty.BringToFront();
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        // Native pixel copies use the control's unscaled coordinate system.
        using var transform = e.Graphics.Transform;
        using var clip = e.Graphics.Clip;
        var previous = copyPixels;
        var previousSettings = paintSettings;
        paintSettings = (e.Graphics.DpiX, e.Graphics.DpiY, e.Graphics.TextRenderingHint, e.Graphics.TextContrast);
        copyPixels = transform.IsIdentity && e.Graphics.PageScale == 1 &&
            e.Graphics.PageUnit is GraphicsUnit.Display or GraphicsUnit.Pixel &&
            (clip.IsInfinite(e.Graphics) || clip.GetRegionScans(transform).Length == 1);
        try { base.OnPaint(e); }
        finally
        {
            try { FlushCopies(e.Graphics); }
            finally
            {
                copyPixels = previous;
                paintSettings = previousSettings;
            }
        }
    }

    protected override void OnRowPostPaint(DataGridViewRowPostPaintEventArgs e)
    {
        FlushCopies(e.Graphics);
        base.OnRowPostPaint(e);
    }

    private void FlushCopies(Graphics graphics)
    {
        if (copies.Count == 0)
            return;

        // Share one destination context per row, before native focus and row decorations are painted.
        var target = graphics.GetHdc();
        try
        {
            foreach (var (source, visible, origin) in copies)
                if (!BitBlt(target, visible.X, visible.Y, visible.Width, visible.Height, source,
                    visible.X - origin.X, visible.Y - origin.Y, 0x00CC0020))
                    throw new Win32Exception();
        }
        finally
        {
            graphics.ReleaseHdc(target);
            copies.Clear();
        }
    }

    internal sealed class TextCell : DataGridViewTextBoxCell
    {
        protected override void Paint(Graphics graphics, Rectangle clipBounds, Rectangle cellBounds, int rowIndex,
            DataGridViewElementStates cellState, object? value, object? formattedValue, string? errorText,
            DataGridViewCellStyle cellStyle, DataGridViewAdvancedBorderStyle advancedBorderStyle,
            DataGridViewPaintParts paintParts)
        {
            // Account for both the bitmap and its retained native drawing surface.
            var bytes = (long)cellBounds.Width * cellBounds.Height * 8;
            if (DataGridView is not ResultGrid { CacheCellRendering: true, ReadOnly: true } owner ||
                !owner.copyPixels ||
                paintParts != DataGridViewPaintParts.All || formattedValue is not string { Length: <= 2048 } text ||
                cellStyle.Font is not { } font || !string.IsNullOrEmpty(errorText) ||
                cellStyle.BackColor.A != 255 || cellStyle.SelectionBackColor.A != 255 ||
                cellBounds.Width <= 0 || cellBounds.Height <= 0 || bytes > 1024 * 1024 ||
                owner.Focused && owner.CurrentCellAddress == new Point(ColumnIndex, rowIndex))
            {
                base.Paint(graphics, clipBounds, cellBounds, rowIndex, cellState, value, formattedValue, errorText,
                    cellStyle, advancedBorderStyle, paintParts);
                return;
            }

            // Reuse the native cell's pixels while keeping its values, tooltips, and accessibility unchanged.
            if (!ReferenceEquals(owner.cachedFont, font))
            {
                owner.cachedFont = font;
                owner.cachedFontName = font.Name;
            }
            var metrics = owner.paintSettings;
            var key = new CellImageKey(text, owner.cachedFontName, font.Size, font.Style, font.Unit, font.GdiCharSet,
                font.GdiVerticalFont, cellBounds.Size, metrics.DpiX, metrics.DpiY, cellStyle.BackColor,
                cellStyle.ForeColor, cellStyle.SelectionBackColor, cellStyle.SelectionForeColor, owner.GridColor,
                cellStyle.Padding, cellStyle.Alignment, cellStyle.WrapMode, owner.RightToLeft, cellState,
                metrics.Hint, metrics.Contrast,
                advancedBorderStyle.Top, advancedBorderStyle.Bottom,
                    advancedBorderStyle.Left, advancedBorderStyle.Right);
            if (!owner.images.TryGetValue(key, out var image))
            {
                // Bound bitmap storage and resource counts during long scrolling sessions.
                bytes += text.Length * 2 + 256;
                while (owner.recent.First is { } oldest &&
                    (owner.cachedBytes + bytes > CacheBudget || owner.images.Count >= 512))
                {
                    // Finish queued copies before releasing their source surfaces.
                    owner.FlushCopies(graphics);
                    owner.images.Remove(oldest.Value.Key);
                    owner.recent.RemoveFirst();
                    owner.cachedBytes -= oldest.Value.Bytes;
                    oldest.Value.Dispose();
                }
                var bitmap = new Bitmap(cellBounds.Width, cellBounds.Height, PixelFormat.Format32bppRgb);
                Graphics? surface = null;
                nint context = 0;
                try
                {
                    bitmap.SetResolution(metrics.DpiX, metrics.DpiY);
                    surface = Graphics.FromImage(bitmap);
                    var bounds = new Rectangle(Point.Empty, cellBounds.Size);

                    // Preserve the native font rasterization when rendering into an off-screen cell surface.
                    context = surface.GetHdc();
                    {
                        using var raster = Graphics.FromHdc(context);
                        raster.TextRenderingHint = metrics.Hint;
                        raster.TextContrast = metrics.Contrast;
                        base.Paint(raster, bounds, bounds, rowIndex, cellState, value, formattedValue, errorText,
                            cellStyle, advancedBorderStyle, paintParts);
                    }
                    image = owner.recent.AddLast(new CellImage(key, bitmap, surface, context, bytes));
                    owner.images.Add(key, image);
                    owner.cachedBytes += bytes;
                }
                catch
                {
                    if (context != 0)
                        surface!.ReleaseHdc(context);
                    surface?.Dispose();
                    bitmap.Dispose();
                    throw;
                }
            }
            else if (image != owner.recent.Last)
            {
                owner.recent.Remove(image);
                owner.recent.AddLast(image);
            }

            // Copy only visible pixels; the native destination also retains its window clipping region.
            var visible = Rectangle.Intersect(cellBounds, Rectangle.Intersect(clipBounds,
                Rectangle.Ceiling(graphics.VisibleClipBounds)));
            if (visible.IsEmpty)
                return;
            owner.copies.Add((image.Value.Context, visible, cellBounds.Location));
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            copies.Clear();
            foreach (var image in recent)
                image.Dispose();
            images.Clear();
            recent.Clear();
            cachedBytes = 0;
            cachedFont = null;
        }
        base.Dispose(disposing);
    }
}
