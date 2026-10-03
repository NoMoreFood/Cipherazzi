using System.ComponentModel;
using System.Drawing.Imaging;
using System.Drawing.Text;

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
    private sealed record CellImage(CellImageKey Key, Bitmap Bitmap, long Bytes);
    private readonly Dictionary<CellImageKey, LinkedListNode<CellImage>> images = [];
    private readonly LinkedList<CellImage> recent = [];
    private long cachedBytes;
    private readonly EmptyState empty = new() { Visible = false };
    private bool hasEmptyState;
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

    internal sealed class TextCell : DataGridViewTextBoxCell
    {
        protected override void Paint(Graphics graphics, Rectangle clipBounds, Rectangle cellBounds, int rowIndex,
            DataGridViewElementStates cellState, object? value, object? formattedValue, string? errorText,
            DataGridViewCellStyle cellStyle, DataGridViewAdvancedBorderStyle advancedBorderStyle,
            DataGridViewPaintParts paintParts)
        {
            var bytes = (long)cellBounds.Width * cellBounds.Height * 4;
            if (DataGridView is not ResultGrid { CacheCellRendering: true, ReadOnly: true } owner ||
                paintParts != DataGridViewPaintParts.All || formattedValue is not string { Length: <= 2048 } text ||
                cellStyle.Font is not { } font || !string.IsNullOrEmpty(errorText) ||
                cellStyle.BackColor.A != 255 || cellStyle.SelectionBackColor.A != 255 ||
                cellBounds.Width <= 0 || cellBounds.Height <= 0 || bytes > 512 * 1024 ||
                owner.Focused && owner.CurrentCellAddress == new Point(ColumnIndex, rowIndex))
            {
                base.Paint(graphics, clipBounds, cellBounds, rowIndex, cellState, value, formattedValue, errorText,
                    cellStyle, advancedBorderStyle, paintParts);
                return;
            }

            // Reuse the native cell's pixels while keeping its values, tooltips, and accessibility unchanged.
            var key = new CellImageKey(text, font.Name, font.Size, font.Style, font.Unit, font.GdiCharSet,
                font.GdiVerticalFont, cellBounds.Size, graphics.DpiX, graphics.DpiY, cellStyle.BackColor,
                cellStyle.ForeColor, cellStyle.SelectionBackColor, cellStyle.SelectionForeColor, owner.GridColor,
                cellStyle.Padding, cellStyle.Alignment, cellStyle.WrapMode, owner.RightToLeft, cellState,
                graphics.TextRenderingHint, graphics.TextContrast,
                advancedBorderStyle.Top, advancedBorderStyle.Bottom, advancedBorderStyle.Left, advancedBorderStyle.Right);
            if (!owner.images.TryGetValue(key, out var image))
            {
                // Bound bitmap storage and resource counts during long scrolling sessions.
                bytes += text.Length * 2 + 256;
                while (owner.recent.First is { } oldest &&
                    (owner.cachedBytes + bytes > CacheBudget || owner.images.Count >= 512))
                {
                    owner.images.Remove(oldest.Value.Key);
                    owner.recent.RemoveFirst();
                    owner.cachedBytes -= oldest.Value.Bytes;
                    oldest.Value.Bitmap.Dispose();
                }
                var bitmap = new Bitmap(cellBounds.Width, cellBounds.Height, PixelFormat.Format32bppRgb);
                try
                {
                    bitmap.SetResolution(graphics.DpiX, graphics.DpiY);
                    using var surface = Graphics.FromImage(bitmap);
                    var bounds = new Rectangle(Point.Empty, cellBounds.Size);

                    // Preserve the native font rasterization when rendering into an off-screen cell surface.
                    var context = surface.GetHdc();
                    try
                    {
                        using var raster = Graphics.FromHdc(context);
                        raster.TextRenderingHint = graphics.TextRenderingHint;
                        raster.TextContrast = graphics.TextContrast;
                        base.Paint(raster, bounds, bounds, rowIndex, cellState, value, formattedValue, errorText,
                            cellStyle, advancedBorderStyle, paintParts);
                    }
                    finally
                    {
                        surface.ReleaseHdc(context);
                    }
                    image = owner.recent.AddLast(new CellImage(key, bitmap, bytes));
                    owner.images.Add(key, image);
                    owner.cachedBytes += bytes;
                }
                catch
                {
                    bitmap.Dispose();
                    throw;
                }
            }
            else if (image != owner.recent.Last)
            {
                owner.recent.Remove(image);
                owner.recent.AddLast(image);
            }
            graphics.DrawImageUnscaled(image.Value.Bitmap, cellBounds.Location);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            foreach (var image in recent)
                image.Bitmap.Dispose();
            images.Clear();
            recent.Clear();
            cachedBytes = 0;
        }
        base.Dispose(disposing);
    }
}
