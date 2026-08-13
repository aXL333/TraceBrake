using Foreman.Core.Behavior;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using Foreman.McpServer;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

namespace Foreman.App.Windows;

/// <summary>
/// Read-only, verbose at-a-glance view of a single harness: live resource usage (CPU/RAM/GPU/Net/I/O),
/// behavior &amp; escalation, MCP sessions, and its process tree. Opened from a dashboard harness card/chip.
/// Refreshes on its own 2s cadence so the usage bars feel live.
/// </summary>
[SupportedOSPlatform("windows")]
public partial class HarnessDetailWindow : Window
{
    private readonly HarnessDetailContext _ctx;
    private readonly UiTelemetryCache _telemetry;
    private readonly DispatcherTimer _timer;
    private readonly ObservableCollection<UsageBarVm> _usage = [];
    private readonly long _physicalMemBytes = ReadPhysicalMemoryBytes();
    private int _lastWakeLocks;          // cached; the powercfg probe runs off the UI thread (was the open lag)
    private bool _wakeProbeInFlight;

    public HarnessDetailWindow(HarnessDetailContext ctx)
    {
        _ctx = ctx;
        // Background resource sampling for this harness's process tree — keeps the slow GPU perf-counter
        // enumeration off the dispatcher (the UI reads the latest snapshot each 2s tick).
        _telemetry = new UiTelemetryCache(() => _ctx.GetProcesses().Select(p => p.Pid).ToList());
        InitializeComponent();

        UsageBars.ItemsSource = _usage;
        _usage.Add(new UsageBarVm("CPU", Color.FromRgb(0x66, 0xAA, 0xFF)));
        _usage.Add(new UsageBarVm("RAM", Color.FromRgb(0x7E, 0xC8, 0x78)));
        _usage.Add(new UsageBarVm("GPU", Color.FromRgb(0xCC, 0x77, 0xFF)));
        _usage.Add(new UsageBarVm("Net", Color.FromRgb(0x66, 0xCC, 0xAA)));
        _usage.Add(new UsageBarVm("Disk I/O", Color.FromRgb(0xE8, 0xB2, 0x3C)));

        var known = KnownHarnesses.GetById(_ctx.HarnessId);
        TitleText.Text = known?.DisplayName ?? _ctx.HarnessId;
        SubtitleText.Text = known is null
            ? _ctx.HarnessId
            : $"{known.Developer}  ·  {_ctx.HarnessId}";
        DescriptionText.Text = known?.Description ?? string.Empty;

        Refresh();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
    }

    private void Refresh()
    {
        var procs = _ctx.GetProcesses().ToList();
        var profile = _ctx.GetProfile();
        var clients = _ctx.GetClients();
        var settings = _ctx.GetSettings();
        var running = procs.Count > 0;
        var mcpConnected = clients.Any(c => SseSessionManager.MatchesHarness(c.Name, null, _ctx.HarnessId));

        // ── Status badge ──────────────────────────────────────────────────────
        var (badgeText, badgeBg, badgeFg) = running
            ? ("RUNNING", Color.FromRgb(0x1A, 0x3A, 0x1A), Color.FromRgb(0x7E, 0xC8, 0x78))
            : ("IDLE", Color.FromRgb(0x1E, 0x20, 0x28), Color.FromRgb(0x7A, 0x80, 0x90));
        StatusBadgeText.Text = badgeText;
        StatusBadgeText.Foreground = new SolidColorBrush(badgeFg);
        StatusBadge.Background = new SolidColorBrush(badgeBg);

        // ── Badges row (trust, escalation, mcp) ─────────────────────────────────
        var trust = settings.HarnessTrust.TryGetValue(_ctx.HarnessId, out var t) ? Math.Clamp(t, 1, 5) : 3;
        var level = profile?.CurrentLevel ?? EscalationLevel.Watch;
        BadgePanel.Children.Clear();
        AddBadge($"Trust {trust}", Color.FromRgb(0x2A, 0x24, 0x10), Color.FromRgb(0xF0, 0xB8, 0x4A));
        var (escBg, escFg) = EscalationColors(level);
        AddBadge($"Escalation: {level.ToString().ToUpperInvariant()}", escBg, escFg);
        // configured-but-not-connected (and running) → "Ready" (amber): links on first TraceBrake tool call, not a dead-end "No MCP".
        var configured = !mcpConnected && running && (_ctx.IsConfigured?.Invoke() ?? false);
        var (mcpText, mcpBg, mcpFg) = mcpConnected
            ? ("MCP linked", Color.FromRgb(0x12, 0x2A, 0x1C), Color.FromRgb(0x6E, 0xC8, 0x8E))
            : configured
                ? ("MCP: Ready", Color.FromRgb(0x2A, 0x24, 0x10), Color.FromRgb(0xE8, 0xB2, 0x3C))
                : ("No MCP", Color.FromRgb(0x22, 0x16, 0x16), Color.FromRgb(0xC8, 0x7E, 0x7E));
        AddBadge(mcpText, mcpBg, mcpFg);

        // Context budget badge — the agent's self-reported remaining context (report_usage). Green/amber/red by
        // how much is left; absent when the agent hasn't reported.
        if (_ctx.GetContextUsage?.Invoke() is { RemainingPercent: { } pct })
        {
            var (cbg, cfg) = pct >= 50 ? (Color.FromRgb(0x12, 0x2A, 0x1C), Color.FromRgb(0x7E, 0xC8, 0x78))
                           : pct >= 20 ? (Color.FromRgb(0x2A, 0x24, 0x10), Color.FromRgb(0xE8, 0xB2, 0x3C))
                           :             (Color.FromRgb(0x2A, 0x12, 0x12), Color.FromRgb(0xE0, 0x6C, 0x6C));
            AddBadge($"ctx {pct:0}% left", cbg, cfg);
        }

        // ── Live usage ──────────────────────────────────────────────────────────
        UpdateUsage(procs, running);

        // ── Behavior & security ───────────────────────────────────────────────
        BehaviorRows.ItemsSource = BuildBehaviorRows(profile);

        // ── MCP sessions ──────────────────────────────────────────────────────
        var matching = clients
            .Where(c => SseSessionManager.MatchesHarness(c.Name, null, _ctx.HarnessId))
            .Select(c =>
                $"{c.Name}{(string.IsNullOrWhiteSpace(c.Version) ? "" : $" v{c.Version}")}  ·  " +
                $"sampling: {(c.Sampling ? "yes" : "no")}  ·  elicitation: {(c.Elicitation ? "yes" : "no")}")
            .ToList();
        McpRows.ItemsSource = matching;
        NoMcpText.Visibility = matching.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        // ── Processes ─────────────────────────────────────────────────────────
        var metrics = running
            ? _telemetry.Latest
            : new Dictionary<int, ResourceSampler.Metrics>();

        ProcessHeader.Text = $"PROCESSES ({procs.Count})";
        ProcessRows.ItemsSource = procs
            .OrderByDescending(p => metrics.TryGetValue(p.Pid, out var m) ? m.CpuPercent : 0)
            .Select(p =>
            {
                metrics.TryGetValue(p.Pid, out var m);
                return new ProcessRowVm(p, m, _ctx.GetNetRate?.Invoke(p.Pid));
            })
            .ToList();
        NoProcessText.Visibility = procs.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        // Net column needs the elevated sidecar; hint when it's not the source.
        var netSampled = _ctx.GetNetRate is not null;
        UsageHintText.Text = netSampled ? string.Empty : "Net needs elevated sidecar";

        UpdatedText.Text = $"updated {DateTime.Now:HH:mm:ss}";
        ConnectButton.Visibility = mcpConnected ? Visibility.Collapsed : Visibility.Visible;

        FetchWakeLocksAsync();   // powercfg shell-out — never block the UI thread (that was the open lag)
    }

    // The wake-lock count comes from `powercfg /requests` via the elevated sidecar — a blocking call that froze
    // the window on open + every 2s tick. Fetch it off-thread, cache it, and re-render the behavior rows when it
    // changes. One probe in flight at a time.
    private void FetchWakeLocksAsync()
    {
        if (_wakeProbeInFlight) return;
        _wakeProbeInFlight = true;
        System.Threading.Tasks.Task.Run(() => { try { return _ctx.GetWakeLocks(); } catch { return 0; } })
            .ContinueWith(t =>
            {
                _wakeProbeInFlight = false;
                if (t.Status != System.Threading.Tasks.TaskStatus.RanToCompletion || t.Result == _lastWakeLocks) return;
                _lastWakeLocks = t.Result;
                BehaviorRows.ItemsSource = BuildBehaviorRows(_ctx.GetProfile());   // re-render with the fresh count
            }, System.Threading.Tasks.TaskScheduler.FromCurrentSynchronizationContext());
    }

    private void UpdateUsage(IReadOnlyList<ProcessRecord> procs, bool running)
    {
        NoUsageText.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
        UsageBars.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        if (!running)
            return;

        var metrics = _telemetry.Latest;
        var usage = HarnessUsageAggregator.Aggregate(procs, metrics, _ctx.GetNetRate);

        // CPU: percent of a single core's worth of time (tree sum); bar clamps at 100%.
        _usage[0].Set(Math.Min(usage.CpuPercent / 100.0, 1.0), HarnessUsageAggregator.FormatCpu(usage.CpuPercent));

        // RAM: absolute, with bar relative to physical memory when known.
        var ramFraction = _physicalMemBytes > 0 ? (double)usage.MemoryBytes / _physicalMemBytes : 0;
        _usage[1].Set(ramFraction, HarnessUsageAggregator.FormatMem(usage.MemoryBytes));

        // GPU: peak engine utilization across the tree (null when no GPU counters).
        if (usage.GpuPercent is { } gpu)
            _usage[2].Set(Math.Min(gpu / 100.0, 1.0), $"{gpu:0}%");
        else
            _usage[2].Set(0, "n/a");

        // Net: bytes/sec, scaled to a 5 MB/s bar. Null = no sidecar.
        if (usage.NetBytesPerSec is { } net)
            _usage[3].Set(Math.Min(net / (5.0 * 1024 * 1024), 1.0), HarnessUsageAggregator.FormatRate(net));
        else
            _usage[3].Set(0, "—");

        // Disk/other I/O: bytes/sec, scaled to a 50 MB/s bar.
        _usage[4].Set(Math.Min(usage.IoBytesPerSec / (50.0 * 1024 * 1024), 1.0),
            HarnessUsageAggregator.FormatRate(usage.IoBytesPerSec));
    }

    private List<KeyValuePair<string, string>> BuildBehaviorRows(BehaviorProfile? profile)
    {
        var rows = new List<KeyValuePair<string, string>>();
        if (profile is null)
        {
            rows.Add(new("Alerts this session", "0 — no behavior recorded yet"));
            rows.Add(new("Pending Ask Harness", _ctx.GetPendingAsk().ToString(CultureInfo.InvariantCulture)));
            if (_lastWakeLocks > 0) rows.Add(new("Wake locks", _lastWakeLocks.ToString(CultureInfo.InvariantCulture)));
            return rows;
        }

        rows.Add(new("Escalation level", profile.CurrentLevel.ToString()));
        rows.Add(new("Total alerts", profile.TotalAlerts.ToString(CultureInfo.InvariantCulture)));
        rows.Add(new("Distinct rules", profile.UniqueRulesCount.ToString(CultureInfo.InvariantCulture)));

        var cats = profile.Categories;
        if (cats.Count > 0)
            rows.Add(new("Categories", string.Join(", ", cats).ToUpperInvariant()));

        var rules = profile.UniqueRules;
        if (rules.Count > 0)
            rows.Add(new("Rules fired", string.Join(", ", rules)));

        var sev = new[] { "Critical", "High", "Medium", "Low" }
            .Select(s => (s, n: profile.GetSeverityCount(s)))
            .Where(x => x.n > 0)
            .Select(x => $"{x.n} {x.s}")
            .ToList();
        if (sev.Count > 0)
            rows.Add(new("By severity", string.Join("  ·  ", sev)));

        rows.Add(new("Session length", FormatDuration(profile.SessionDuration)));
        if (profile.LastAlertTime != default)
            rows.Add(new("Last alert", RelativeTime(profile.LastAlertTime)));

        var pending = _ctx.GetPendingAsk();
        rows.Add(new("Pending Ask Harness", pending == 0
            ? "none"
            : $"{pending} awaiting reply"));

        if (_lastWakeLocks > 0)
            rows.Add(new("Wake locks", $"{_lastWakeLocks} attributed"));

        return rows;
    }

    private void AddBadge(string text, Color bg, Color fg)
    {
        BadgePanel.Children.Add(new Border
        {
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(8, 3, 8, 3),
            Margin = new Thickness(0, 0, 8, 0),
            Background = new SolidColorBrush(bg),
            Child = new TextBlock
            {
                Text = text,
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(fg),
            },
        });
    }

    private static (Color bg, Color fg) EscalationColors(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => (Color.FromRgb(0x44, 0x0A, 0x0A), Color.FromRgb(0xFF, 0x66, 0x66)),
        EscalationLevel.Alarm     => (Color.FromRgb(0x3A, 0x20, 0x08), Color.FromRgb(0xFF, 0xAA, 0x44)),
        EscalationLevel.Alert     => (Color.FromRgb(0x30, 0x28, 0x08), Color.FromRgb(0xE8, 0xB2, 0x3C)),
        _                         => (Color.FromRgb(0x1A, 0x1C, 0x28), Color.FromRgb(0x7A, 0x80, 0x90)),
    };

    private static string FormatDuration(TimeSpan d)
    {
        if (d.TotalMinutes < 1) return "<1m";
        if (d.TotalHours < 1) return $"{(int)d.TotalMinutes}m";
        if (d.TotalDays < 1) return $"{(int)d.TotalHours}h {d.Minutes:D2}m";
        return $"{(int)d.TotalDays}d {d.Hours}h";
    }

    private static string RelativeTime(DateTimeOffset ts)
    {
        var ago = DateTimeOffset.UtcNow - ts;
        if (ago.TotalSeconds < 30) return "just now";
        if (ago.TotalMinutes < 60) return $"{Math.Max(1, (int)ago.TotalMinutes)}m ago";
        if (ago.TotalHours < 24) return $"{(int)ago.TotalHours}h ago";
        return $"{(int)ago.TotalDays}d ago";
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetPhysicallyInstalledSystemMemory(out long totalMemoryInKilobytes);

    private static long ReadPhysicalMemoryBytes()
    {
        try { return GetPhysicallyInstalledSystemMemory(out var kb) ? kb * 1024L : 0; }
        catch { return 0; }
    }

    private void OpenSettingsClick(object sender, RoutedEventArgs e)
    {
        _ctx.OpenSettings();
        Refresh();
    }

    private void ConnectAgentClick(object sender, RoutedEventArgs e) => _ctx.OpenConnectAgent();

    // ── On-click operations ───────────────────────────────────────────────────

    private void HealthCheckClick(object sender, RoutedEventArgs e)
    {
        HealthRows.ItemsSource = RunHealthCheck();
        HealthRows.Visibility = Visibility.Visible;
    }

    // A Foreman-side integration self-test: is this harness wired up and healthy? Computed from data Foreman
    // already has — no round-trip needed — so it's instant and works even when the agent is idle.
    private List<HealthRowVm> RunHealthCheck()
    {
        var procs = _ctx.GetProcesses().ToList();
        var clients = _ctx.GetClients();
        var profile = _ctx.GetProfile();
        var running = procs.Count > 0;
        var mcp = clients.Any(c => SseSessionManager.MatchesHarness(c.Name, null, _ctx.HarnessId));
        var hasProfile = !string.IsNullOrEmpty(HarnessIntegrationRegistry.GetDefaultProfileName(_ctx.HarnessId));
        var usage = _ctx.GetContextUsage?.Invoke();
        var pending = _ctx.GetPendingAsk();
        var level = profile?.CurrentLevel ?? EscalationLevel.Watch;

        return
        [
            new(running ? "ok" : "info", "Process detected",
                running ? $"{procs.Count} process(es) tracked" : "not currently running"),
            new(mcp ? "ok" : "warn", "MCP session live",
                mcp ? "connected — Ask Harness + usage available" : "no live session — reconnect to enable Ask Harness / live detail / usage"),
            new(hasProfile ? "ok" : "fail", "Permission profile",
                hasProfile ? "profile applies — command/file enforcement active" : "no profile — running monitor-only"),
            new(usage is not null ? "ok" : "info", "Context usage",
                usage?.ShortLabel is { } s ? $"{s} (self-reported)" : "agent hasn't called report_usage"),
            new(pending == 0 ? "ok" : "warn", "Ask Harness queue",
                pending == 0 ? "no pending prompts" : $"{pending} awaiting reply"),
            new(level <= EscalationLevel.Watch ? "ok" : "warn", "Escalation",
                level <= EscalationLevel.Watch ? "calm (Watch)" : level.ToString().ToUpperInvariant()),
        ];
    }

    private void ContextBudgetClick(object sender, RoutedEventArgs e)
    {
        var u = _ctx.GetContextUsage?.Invoke();
        if (u is null)
        {
            ShowActionResult("No context budget reported yet. The agent reports it via the report_usage MCP tool — " +
                "make sure it's MCP-connected (Connect agent) and its instructions tell it to report at task boundaries.");
            return;
        }
        var parts = new List<string>();
        if (u.RemainingPercent is { } p) parts.Add($"{p:0}% remaining");
        if (u.TokensUsed is { } used && u.TokensBudget is { } bud) parts.Add($"{used:N0} / {bud:N0} tokens");
        else if (u.TokensUsed is { } onlyUsed) parts.Add($"{onlyUsed:N0} tokens used");
        if (!string.IsNullOrWhiteSpace(u.Note)) parts.Add($"“{u.Note}”");
        parts.Add($"reported {RelativeTime(u.ReportedAtUtc)}");
        ShowActionResult("Context budget — " + string.Join("  ·  ", parts));
    }

    private void CopySummaryClick(object sender, RoutedEventArgs e)
    {
        var procs = _ctx.GetProcesses().ToList();
        var profile = _ctx.GetProfile();
        var mcp = _ctx.GetClients().Any(c => SseSessionManager.MatchesHarness(c.Name, null, _ctx.HarnessId));
        var u = _ctx.GetContextUsage?.Invoke();
        var summary =
            $"{TitleText.Text} ({_ctx.HarnessId}) · {(procs.Count > 0 ? "running" : "idle")} · " +
            $"{(mcp ? "MCP linked" : "no MCP")} · escalation {(profile?.CurrentLevel ?? EscalationLevel.Watch)} · " +
            $"{profile?.TotalAlerts ?? 0} alerts" +
            (u?.ShortLabel is { } s ? $" · {s}" : "") +
            (procs.Count > 0 ? $" · {procs.Count} proc(s)" : "");
        try { Clipboard.SetText(summary); ShowActionResult("Copied: " + summary); }
        catch (Exception ex) { ShowActionResult("Couldn't copy: " + ex.Message); }
    }

    private void RequestCleanupClick(object sender, RoutedEventArgs e)
    {
        if (_ctx.RequestCleanup is null) { ShowActionResult("Self-cleanup isn't available for this harness."); return; }
        var (_, msg) = _ctx.RequestCleanup();
        ShowActionResult(msg);
    }

    private void ResetMetricsClick(object sender, RoutedEventArgs e)
    {
        if (_ctx.ResetMetrics is null) { ShowActionResult("Reset isn't available."); return; }
        _ctx.ResetMetrics();
        ShowActionResult("Behavior / escalation metrics reset for this harness.");
        Refresh();
    }

    private void ShowActionResult(string msg)
    {
        ActionResultText.Text = msg;
        ActionResultText.Visibility = Visibility.Visible;
    }

    private void CloseClick(object sender, RoutedEventArgs e) => Close();

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        _telemetry.Dispose();
        base.OnClosed(e);
    }
}

/// <summary>Data + action providers the detail window reads live, supplied by the dashboard.</summary>
public sealed class HarnessDetailContext
{
    public required string HarnessId { get; init; }
    public required Func<IEnumerable<ProcessRecord>> GetProcesses { get; init; }
    public required Func<BehaviorProfile?> GetProfile { get; init; }
    public required Func<IReadOnlyList<McpClientInfo>> GetClients { get; init; }
    public required Func<ForemanSettings> GetSettings { get; init; }
    public required Func<int> GetPendingAsk { get; init; }
    public required Func<int> GetWakeLocks { get; init; }
    public Func<int, double?>? GetNetRate { get; init; }
    public required Action OpenSettings { get; init; }
    public required Action OpenConnectAgent { get; init; }

    /// <summary>Whether this harness's config already points at TraceBrake (so a not-connected running agent just needs a restart).</summary>
    public Func<bool>? IsConfigured { get; init; }

    // ── On-click operations (optional; null = button reports "not available") ──
    public Func<HarnessContextUsage?>? GetContextUsage { get; init; }
    public Func<(bool Ok, string Message)>? RequestCleanup { get; init; }
    public Action? ResetMetrics { get; init; }
}

/// <summary>One row in the integration health check (✓/!/✕/•).</summary>
public sealed class HealthRowVm
{
    public string Symbol { get; }
    public Brush SymbolBrush { get; }
    public string Label { get; }
    public string Detail { get; }

    public HealthRowVm(string status, string label, string detail)
    {
        Label = label;
        Detail = detail;
        (Symbol, SymbolBrush) = status switch
        {
            "ok"   => ("✓", new SolidColorBrush(Color.FromRgb(0x7E, 0xC8, 0x78))),
            "warn" => ("!", new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
            "fail" => ("✕", new SolidColorBrush(Color.FromRgb(0xE0, 0x6C, 0x6C))),
            _      => ("•", new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
        };
    }
}

/// <summary>One live usage bar (CPU/RAM/GPU/Net/I/O).</summary>
public sealed class UsageBarVm : INotifyPropertyChanged
{
    private double _fraction;
    private string _valueText = "—";

    public string Label { get; }
    public Brush BarBrush { get; }

    public UsageBarVm(string label, Color barColor)
    {
        Label = label;
        BarBrush = new SolidColorBrush(barColor);
    }

    public double Fraction
    {
        get => _fraction;
        private set { _fraction = value; OnChanged(nameof(Fraction)); }
    }

    public string ValueText
    {
        get => _valueText;
        private set { _valueText = value; OnChanged(nameof(ValueText)); }
    }

    public void Set(double fraction, string valueText)
    {
        Fraction = Math.Clamp(fraction, 0, 1);
        ValueText = valueText;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>One process row in the harness's tree.</summary>
public sealed class ProcessRowVm
{
    public string Name { get; }
    public string PidLabel { get; }
    public string CommandLine { get; }
    public string UsageLabel { get; }

    public ProcessRowVm(ProcessRecord p, ResourceSampler.Metrics metrics, double? netRate)
    {
        Name = p.Name;
        PidLabel = $"pid {p.Pid}";
        CommandLine = string.IsNullOrWhiteSpace(p.CommandLine)
            ? SecretRedactor.Redact(p.ExecutablePath)
            : SecretRedactor.Redact(p.CommandLine);

        var parts = new List<string>
        {
            $"{HarnessUsageAggregator.FormatCpu(metrics.CpuPercent)} CPU",
            $"{HarnessUsageAggregator.FormatMem(metrics.MemoryBytes)}",
        };
        if (metrics.GpuPercent is > 0.5)
            parts.Add($"{metrics.GpuPercent:0}% GPU");
        if (netRate is > 0)
            parts.Add(HarnessUsageAggregator.FormatRate(netRate.Value));
        UsageLabel = string.Join("  ·  ", parts);
    }
}

/// <summary>Converts a 0..1 usage fraction into the fill / remainder star columns of a bar.</summary>
public sealed class UsageFillConverter : IValueConverter
{
    public string Mode { get; set; } = "Fill";

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var fraction = value is double d ? Math.Clamp(d, 0, 1) : 0;
        return Mode.Equals("Rest", StringComparison.OrdinalIgnoreCase)
            ? new GridLength(1 - fraction, GridUnitType.Star)
            : new GridLength(fraction, GridUnitType.Star);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
