using System.Drawing;
using System.Windows;

namespace Foreman.App.Tray;

/// <summary>
/// TraceBrake's HAL-style monocle tray icons. The lens/status glow changes colour while the
/// silhouette stays identical to the app, window, shortcut and installer mark, so status remains
/// visible without introducing a separate tray-only logo.
/// </summary>
public static class TrayIconSet
{
    public static Icon Green { get; } = LoadResourceIcon("foreman-green.ico");
    public static Icon Amber { get; } = LoadResourceIcon("foreman-amber.ico");
    public static Icon Red   { get; } = LoadResourceIcon("foreman-red.ico");

    private static Icon LoadResourceIcon(string fileName)
    {
        var uri = new Uri($"/Resources/{fileName}", UriKind.Relative);
        var resource = Application.GetResourceStream(uri)
            ?? throw new InvalidOperationException($"Missing tray icon resource: {fileName}");
        using (resource.Stream)
        using (var source = new Icon(resource.Stream, new System.Drawing.Size(32, 32)))
            return (Icon)source.Clone();
    }
}
