using Foreman.Core.Models;
using Foreman.Monitor;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Foreman.App.Windows;

public partial class ProcessMonitorWindow : UserControl, IDisposable
{
    private readonly Func<IEnumerable<ProcessRecord>> _getSnapshot;
    private readonly Func<int, double?>? _getNetRate;
    private readonly Func<string, (bool Ok, string Message)>? _requestCleanup;
    private readonly Func<string, HarnessTerminationResult>? _killHarness;
    private readonly Func<int, string?>? _resolveHarnessByPid;
    private readonly DispatcherTimer _timer;
    private readonly UiTelemetryCache _telemetry;
    private ProcessMonitorVm? _selected;

    public ProcessMonitorWindow(
        Func<IEnumerable<ProcessRecord>> getSnapshot,
        Func<int, double?>? getNetRate = null,
        Func<string, (bool Ok, string Message)>? requestCleanup = null,
        Func<string, HarnessTerminationResult>? killHarness = null,
        Func<int, string?>? resolveHarnessByPid = null)
    {
        _getSnapshot = getSnapshot;
        _getNetRate  = getNetRate;
        _requestCleanup = requestCleanup;
        _killHarness = killHarness;
        _resolveHarnessByPid = resolveHarnessByPid;
        // Sample resource usage on a background loop; the UI just reads the latest snapshot (the GPU
        // perf-counter enumeration is far too slow to run on the dispatcher every 2s).
        _telemetry = new UiTelemetryCache(() => _getSnapshot().Select(p => p.Pid).ToList());
        InitializeComponent();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => Refresh();
        // Only refresh while this tab is actually shown. A non-selected dashboard tab is UNLOADED by the
        // TabControl, but a DispatcherTimer keeps firing regardless — so a hidden Processes tab was rebuilding
        // the whole live process list (sort + full ItemsSource replace) every 2s for nothing. Start on load,
        // stop on unload (mirrors HarnessesWindow); refresh on show so the tab is never stale.
        Loaded   += (_, _) => { Refresh(); _timer.Start(); };
        Unloaded += (_, _) => _timer.Stop();
    }

    private void Refresh()
    {
        // Guard: the IsChecked="True" filter checkboxes raise Checked during InitializeComponent(),
        // before sibling elements (HideTerminatedCheck / ProcessList / CountLabel) are created. Don't
        // run until the window is actually loaded. (Same XAML-init hazard as LogWindow's filters.)
        if (!IsLoaded) return;

        var records = _getSnapshot().ToList();

        bool harnessOnly    = HarnessOnlyCheck.IsChecked   == true;
        bool hideTerminated = HideTerminatedCheck.IsChecked == true;

        var filteredRecords = records
            .Where(p => !harnessOnly    || p.IsHarness)
            .Where(p => !hideTerminated || p.State != ProcessState.Terminated)
            .OrderByDescending(p => (int)p.State)        // hanging/orphaned first
            .ThenBy(p => p.HarnessType ?? "zzz")
            .ThenBy(p => p.Pid)
            .ToList();

        // Live resource metrics (CPU/mem/I/O/GPU), read from the background sampler's latest snapshot.
        var metrics = _telemetry.Latest;

        var filtered = filteredRecords
            .Select(p => new ProcessMonitorVm(
                p,
                metrics.TryGetValue(p.Pid, out var m) ? m : null,
                FileHashCache.GetOrCompute(p.ExecutablePath),
                _getNetRate?.Invoke(p.Pid)))
            .ToList();

        ProcessList.ItemsSource = filtered;
        CountLabel.Text = $"{filtered.Count} process{(filtered.Count == 1 ? "" : "es")}";

        // re-select previously selected row if it's still present
        if (_selected is not null)
        {
            var match = filtered.FirstOrDefault(v => v.Pid == _selected.Pid);
            if (match is not null)
                ProcessList.SelectedItem = match;
        }
    }

    private void FilterChanged(object sender, RoutedEventArgs e) => Refresh();

    private void ProcessList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _selected = ProcessList.SelectedItem as ProcessMonitorVm;

        if (_selected is null)
        {
            CmdLineDetail.Text = "— select a process —";
            CmdLineDetail.Foreground = (Brush)FindResource("TextMutedBrush");
            CopyPidBtn.IsEnabled = false;
            CopyCmdBtn.IsEnabled = false;
            CopyHashBtn.IsEnabled = false;
        }
        else
        {
            CmdLineDetail.Text = string.IsNullOrEmpty(_selected.CommandLineFull)
                ? "(no command line)"
                : _selected.CommandLineFull;
            CmdLineDetail.Foreground = (Brush)FindResource("TextPrimaryBrush");
            CopyPidBtn.IsEnabled = true;
            CopyCmdBtn.IsEnabled = !string.IsNullOrEmpty(_selected.CommandLineFull);
            CopyHashBtn.IsEnabled = _selected.HashFull is { Length: > 0 };
        }
    }

    private void CopyPidClick(object sender, RoutedEventArgs e)
    {
        if (_selected is not null)
            Clipboard.SetText(_selected.Pid.ToString());
    }

    private void CopyCmdClick(object sender, RoutedEventArgs e)
    {
        if (_selected?.CommandLineFull is { Length: > 0 } cmd)
            Clipboard.SetText(cmd);
    }

    // ── Executable / hash actions (right-click context menu) ──────────────────

    // Right-click should act on the row under the cursor, so select it first.
    private void ProcessList_RightButtonDown(object sender, MouseButtonEventArgs e)
    {
        var dep = e.OriginalSource as DependencyObject;
        while (dep is not null and not ListViewItem)
            dep = VisualTreeHelper.GetParent(dep);
        if (dep is ListViewItem item)
            item.IsSelected = true;
    }

    private void VirusTotalClick(object sender, RoutedEventArgs e)
    {
        if (_selected?.HashFull is { Length: > 0 } hash)
            OpenUrl($"https://www.virustotal.com/gui/file/{hash.ToLowerInvariant()}");
        else
            MessageBox.Show(
                "No SHA-256 yet for this process's executable — it may still be hashing in the background, " +
                "or the file path is empty/unreadable at this privilege level.",
                "TraceBrake — VirusTotal", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CopyHashClick(object sender, RoutedEventArgs e)
    {
        if (_selected?.HashFull is { Length: > 0 } hash) Clipboard.SetText(hash);
    }

    private void CopyPathClick(object sender, RoutedEventArgs e)
    {
        if (_selected?.ExecutablePath is { Length: > 0 } path) Clipboard.SetText(path);
    }

    // ── Idle Harness self-cleanup (right-click on a harness row) ───────────────

    private void RequestCleanupClick(object sender, RoutedEventArgs e)
    {
        if (_requestCleanup is null) return;

        var harnessId = SelectedHarnessId();
        if (string.IsNullOrEmpty(harnessId))
        {
            MessageBox.Show(
                "Select a row that belongs to a harness first — the cleanup request goes to the whole agent, " +
                "asking it to checkpoint work, stop leftover children, and reply or exit.",
                "TraceBrake — Self-cleanup", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var (ok, msg) = _requestCleanup(harnessId);
        MessageBox.Show(msg, "TraceBrake — Self-cleanup",
            MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private void KillHarnessClick(object sender, RoutedEventArgs e)
    {
        if (_killHarness is null) return;

        var harnessId = SelectedHarnessId();
        if (string.IsNullOrEmpty(harnessId))
        {
            MessageBox.Show(
                "TraceBrake cannot attribute the selected process to a harness. Select the agent's root process or a known child process first.",
                "TraceBrake — End Harness Processes", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var answer = MessageBox.Show(
            $"End every running process tree owned by '{harnessId}'?\n\n" +
            "TraceBrake will re-check each live process identity, then immediately terminate the complete tree. " +
            "Unsaved agent work will be lost.",
            "TraceBrake — Confirm End Harness",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;

        var result = _killHarness(harnessId);
        MessageBox.Show(
            result.OperatorMessage,
            "TraceBrake — End Harness Processes",
            MessageBoxButton.OK,
            result.Complete ? MessageBoxImage.Information : MessageBoxImage.Warning);
        Refresh();
    }

    private string? SelectedHarnessId()
    {
        if (_selected is null) return null;
        return _selected.HarnessId ?? _resolveHarnessByPid?.Invoke(_selected.Pid);
    }

    private void OpenLocationClick(object sender, RoutedEventArgs e)
    {
        if (_selected?.ExecutablePath is { Length: > 0 } path && File.Exists(path))
            try { Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true }); }
            catch { /* explorer not available — nothing to do */ }
    }

    private static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not open the browser.\n\n{ex.Message}", "TraceBrake",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // Called by the host (DashboardWindow) when it closes, since a UserControl has no OnClosed.
    public void Dispose()
    {
        _timer.Stop();
        _telemetry.Dispose();
    }
}

// ─── ViewModel ─────────────────────────────────────────────────────────────────

public sealed class ProcessMonitorVm
{
    // raw for selection continuity
    public int    Pid            { get; }
    public string Name           { get; }
    public string CommandLine    { get; }        // truncated for column display
    public string CommandLineFull { get; }       // full, for detail strip
    public int    ParentPid      { get; }
    public string HarnessType    { get; }        // display label ("—" when none)
    public string? HarnessId     { get; }        // raw harness id, null for non-harness rows
    public string StateLabel     { get; }
    public string UptimeLabel    { get; }
    public string SilentLabel    { get; }
    public Brush  RowForeground  { get; }
    public Brush  RowBackground  { get; }   // Process-Explorer-style row tint by state/role

    // ── Live resource metrics ────────────────────────────────────────────────
    public string CpuLabel { get; }
    public string MemLabel { get; }
    public string IoLabel  { get; }
    public string GpuLabel { get; }
    public string NetLabel { get; }   // live bytes/sec from the elevated sidecar, else "n/a"

    // ── Executable identity ──────────────────────────────────────────────────
    public string  ExecutablePath { get; }
    public string? HashFull       { get; }   // full SHA-256 (for VirusTotal / copy), null if unknown
    public string  HashLabel      { get; }   // short form for the column

    public ProcessMonitorVm(ProcessRecord p, ResourceSampler.Metrics? metrics, string? hash, double? netRate)
    {
        NetLabel        = netRate is { } n ? FormatRate(n) : "n/a";
        Pid             = p.Pid;
        Name            = p.Name;
        CommandLineFull = p.CommandLine;
        CommandLine     = Truncate(p.CommandLine, 80);
        ParentPid       = p.ParentPid;
        HarnessId       = p.HarnessType;
        HarnessType     = p.HarnessType ?? (p.IsHarness ? "harness" : "—");

        ExecutablePath = p.ExecutablePath;
        HashFull       = string.IsNullOrEmpty(hash) ? null : hash;
        HashLabel      = HashFull is { } h               ? h[..12].ToLowerInvariant()
                       : string.IsNullOrWhiteSpace(p.ExecutablePath) ? "—"   // no path to hash
                       :                                  "…";               // computing in background

        // Terminated rows have no live process to sample.
        if (p.State == ProcessState.Terminated || metrics is not { } m)
        {
            CpuLabel = MemLabel = IoLabel = GpuLabel = "—";
        }
        else
        {
            CpuLabel = m.CpuPercent < 0.5 ? "0%" : $"{m.CpuPercent:0}%";
            MemLabel = m.MemoryBytes > 0 ? FormatBytes(m.MemoryBytes) : "—";
            IoLabel  = FormatRate(m.IoBytesPerSec);
            GpuLabel = m.GpuPercent is { } g ? (g < 0.5 ? "0%" : $"{g:0}%") : "n/a";
        }

        StateLabel = p.State switch
        {
            ProcessState.Hanging    => "⚠ Hanging",
            ProcessState.Orphaned   => "⚠ Orphaned",
            ProcessState.Terminated => "✕ Gone",
            _                       => p.IsHarness ? "● Active" : "○ Active",
        };

        UptimeLabel = FormatMinutes(p.UptimeMinutes);
        SilentLabel = p.IoCountersUnavailable ? "n/a" : FormatMinutes(p.SilentMinutes);

        // Color coding (Process-Explorer style): tint the whole row by state/role so the eye finds trouble at a
        // glance. Orphaned (parent gone) = red, Hanging (no I/O) = amber, the harness agent itself = blue, a normal
        // child = neutral, terminated = dim. Selection/hover override the tint in the row style.
        var (fg, bg) = p.State switch
        {
            ProcessState.Orphaned   => (Rgb(0xFF, 0x9A, 0x9A), Rgb(0x3A, 0x1A, 0x1E)),   // red
            ProcessState.Hanging    => (Rgb(0xFF, 0xC8, 0x82), Rgb(0x33, 0x29, 0x1A)),   // amber
            ProcessState.Terminated => (Rgb(0x55, 0x58, 0x60), Brushes.Transparent),     // dim, no tint
            _ => p.IsHarness
                ? (Rgb(0xCF, 0xE0, 0xF0), Rgb(0x16, 0x20, 0x2E))                         // the agent: blue
                : (Rgb(0xA8, 0xB0, 0xBC), Brushes.Transparent),                          // normal child: neutral
        };
        RowForeground = fg;
        RowBackground = bg;
    }

    private static SolidColorBrush Rgb(byte r, byte g, byte b) => new(Color.FromRgb(r, g, b));

    private static string FormatMinutes(int mins)
    {
        if (mins < 1)  return "<1m";
        if (mins < 60) return $"{mins}m";
        var h = mins / 60;
        var m = mins % 60;
        return $"{h}h {m:D2}m";
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private static string FormatBytes(long b) =>
        b >= 1L << 30 ? $"{b / (double)(1 << 30):0.0} GB" :
        b >= 1L << 20 ? $"{b / (double)(1 << 20):0} MB" :
        b >= 1L << 10 ? $"{b / (double)(1 << 10):0} KB" : $"{b} B";

    private static string FormatRate(double bytesPerSec) =>
        bytesPerSec < 1            ? "—" :
        bytesPerSec < 1024         ? $"{bytesPerSec:0} B/s" :
        bytesPerSec < 1024 * 1024  ? $"{bytesPerSec / 1024:0} KB/s" :
                                     $"{bytesPerSec / (1024 * 1024):0.0} MB/s";
}
