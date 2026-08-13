using System.Windows.Controls;
using System.Windows.Media;
using Foreman.Core.Health;

namespace Foreman.App.Windows;

/// <summary>
/// The "Setup" dashboard tab: an at-a-glance checklist of TraceBrake's own posture — launch context, MCP,
/// extension, presence lock, vault, decoys, guardian, OS-log blackbox — with a one-line remedy per row.
/// All judgement lives in <see cref="SetupHealth.Evaluate"/> (Core, tested); this view only renders. The
/// snapshot provider is injected by the tray/App composition root so the view holds no service references.
/// </summary>
public partial class SetupHealthView : UserControl
{
    private readonly Func<SetupHealthSnapshot> _snapshot;

    private static readonly Brush OkBrush        = new SolidColorBrush(Color.FromRgb(0x4C, 0xC3, 0x8A));
    private static readonly Brush AttentionBrush = new SolidColorBrush(Color.FromRgb(0xE5, 0xA5, 0x3A));
    private static readonly Brush OffBrush       = new SolidColorBrush(Color.FromRgb(0x6A, 0x70, 0x7E));
    private static readonly Brush InfoBrush      = new SolidColorBrush(Color.FromRgb(0x5A, 0xA7, 0xE0));

    private sealed record Row(Brush Dot, string Title, string Detail, string Remedy, System.Windows.Visibility RemedyVisibility);

    public SetupHealthView(Func<SetupHealthSnapshot> snapshot)
    {
        _snapshot = snapshot;
        InitializeComponent();
        RefreshState();
    }

    /// <summary>Re-evaluates the checklist; called on construction, tab-show, and the Refresh button.</summary>
    public void RefreshState()
    {
        IReadOnlyList<SetupHealthItem> items;
        try { items = SetupHealth.Evaluate(_snapshot()); }
        catch (Exception ex)
        {
            SummaryText.Text = "Couldn't gather setup state: " + ex.Message;
            Rows.ItemsSource = Array.Empty<Row>();
            return;
        }

        Rows.ItemsSource = items.Select(i => new Row(
            DotFor(i.Status), i.Title, i.Detail, i.Remedy ?? string.Empty,
            string.IsNullOrEmpty(i.Remedy) ? System.Windows.Visibility.Collapsed : System.Windows.Visibility.Visible)).ToList();

        var attention = items.Count(i => i.Status == SetupHealthStatus.Attention);
        var off = items.Count(i => i.Status == SetupHealthStatus.Off);
        SummaryText.Text = attention > 0
            ? $"{attention} item(s) need attention · {off} feature(s) not set up."
            : off > 0
                ? $"All good. {off} optional feature(s) not set up."
                : "All good.";
    }

    private static Brush DotFor(SetupHealthStatus s) => s switch
    {
        SetupHealthStatus.Ok        => OkBrush,
        SetupHealthStatus.Attention => AttentionBrush,
        SetupHealthStatus.Info      => InfoBrush,
        _                           => OffBrush,
    };

    private void RefreshClick(object sender, System.Windows.RoutedEventArgs e) => RefreshState();
}
