using Foreman.Core.Alerts;
using Foreman.Core.Behavior;
using Foreman.Core.Events;
using Foreman.Core.Integration;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Power;
using Foreman.Core.Settings;
using Foreman.McpServer;
using Foreman.Monitor;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Threading.Tasks;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Foreman.App.Windows;

/// <summary>
/// Main at-a-glance dashboard window — opened by left-clicking the tray icon.
/// Shows per-harness escalation status chips, then a scrollable feed of the 50 most
/// recent security-relevant events (command alerts, escalations, hangs, orphans).
/// Clicking any row opens the AlertDetailWindow for that event.
/// Refreshes live (via IEventSink) and every 30 s for relative-time ("X ago") text.
/// </summary>
public partial class DashboardWindow : Window, IEventSink
{
    private readonly Func<IEnumerable<BehaviorProfile>> _getProfiles;
    private readonly ObservableCollection<DashboardAlertVm> _alerts = [];
    private string _lastAlertSig = "";   // so the alert feed only rebuilds (and resets scroll) when events change
    private readonly DispatcherTimer _refreshTimer;
    private readonly DispatcherTimer _usageTimer;
    private readonly UiTelemetryCache _telemetry;
    private IReadOnlyDictionary<int, ResourceSampler.Metrics> _liveMetrics = new Dictionary<int, ResourceSampler.Metrics>();
    private readonly List<IDisposable> _hostedViews = [];

    // "Is this harness configured for Foreman?" reads each agent's config file (and ~/.claude.json can be many
    // MB to parse) — far too heavy for the 5s UI refresh. Recompute off-thread at most every 30s and cache it;
    // the refresh reads the cache. Configured status only changes when you run Connect, so a 30s-stale view is fine.
    private volatile Dictionary<string, bool> _configuredCache = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset _configuredCacheAt = DateTimeOffset.MinValue;
    private bool _configuredRefreshing;
    private HarnessesWindow? _harnessView;
    private LogWindow? _logView;   // for tile deep-links that pre-set the severity filter
    private VaultView? _vaultView; // refreshed when its tab is shown (reflects lock/unlock done elsewhere)
    private CuApprovalsView? _approvalsView; // refreshed when its tab is shown (reflects the live held-action list)
    private SetupHealthView? _setupView; // refreshed when its tab is shown (reflects live service state)
    private MutesView? _mutesView; // refreshed when its tab is shown (reflects mutes added/expired elsewhere)
    private ConnectAgentView? _connectView; // refreshed when its tab is shown (keeps the connected-agent list live)
    private SettingsView? _settingsView; // refreshed when its tab is shown (reflects settings changed elsewhere)

    /// <summary>Wired by TrayController — Settings and Connect-agent stay as separate dialogs.</summary>
    public Action? OpenSettingsRequested { get; set; }

    /// <summary>Live status providers for the strip/footer, wired by TrayController.</summary>
    public Func<int>?  GetMcpClientCount      { get; set; }
    public Func<bool>? GetNetCaptureConnected { get; set; }
    public int         McpPort                { get; set; } = 54321;

    /// <summary>Connected MCP clients + capabilities, for the MCP CLIENTS tooltip.</summary>
    public Func<IReadOnlyList<McpClientInfo>>? GetConnectedClients { get; set; }

    /// <summary>Harness ids that made an authenticated MCP request recently — sticky "connected" (these clients
    /// hold no persistent session, so the live client list reads ~0 between calls).</summary>
    public Func<IReadOnlyCollection<string>>? GetRecentlyConnectedHarnessIds { get; set; }

    /// <summary>Current MCP-server inventory (per harness), for the computer-use / browser-use capability flags.</summary>
    public Func<IReadOnlyList<Foreman.Core.Mcp.McpServerEntry>>? GetMcpInventory { get; set; }

    /// <summary>Live count of agents currently running (distinct harness types), wired by TrayController.</summary>
    public Func<int>? GetRunningAgentCount { get; set; }

    /// <summary>Process snapshot for harness running/MCP attribution.</summary>
    public Func<IEnumerable<ProcessRecord>>? GetProcessSnapshot { get; set; }

    /// <summary>Settings for trust levels and disabled harnesses.</summary>
    public Func<ForemanSettings>? GetSettings { get; set; }

    public Func<string, IEnumerable<ProcessRecord>>? GetProcessesByHarness { get; set; }
    public Func<int, double?>? GetNetRate { get; set; }
    public Func<WakeRequestSnapshot>? GetWakeRequests { get; set; }
    public Func<string?, int>? GetPendingAskCount { get; set; }
    public Func<bool>? GetGameModeActive { get; set; }
    public Func<string?>? GetCuDriver { get; set; }
    public Func<string?, Task<(bool Ok, string Reason)>>? SetCuDriver { get; set; }
    public Func<string?>? GetCuAttentionTab { get; set; }

    /// <summary>An agent's self-reported context/token budget (via the report_usage MCP tool); null if never reported.</summary>
    public Func<string, HarnessContextUsage?>? GetContextUsage { get; set; }

    /// <summary>Polite MCP "pack up cleanly" request for a harness (Idle Harness self-cleanup); wired by TrayController.</summary>
    public Func<string, (bool Ok, string Message)>? RequestHarnessCleanup { get; set; }

    /// <summary>Immediately ends every verified process tree belonging to a harness.</summary>
    public Func<string, HarnessTerminationResult>? KillHarness { get; set; }

    /// <summary>Reset a harness's escalation/behavior metrics; wired by TrayController.</summary>
    public Action<string>? ResetBehaviorMetrics { get; set; }

    /// <summary>Opens the "Connect agent" guide window.</summary>
    public Action? OpenConnectAgentRequested { get; set; }

    /// <summary>Mute/unmute yellow (medium) warning notification toasts; wired by TrayController. true = muted.</summary>
    public Action<bool>? SetWarningsMuted { get; set; }

    public DashboardWindow(Func<IEnumerable<BehaviorProfile>> getProfiles)
    {
        _getProfiles = getProfiles;
        InitializeComponent();

        AlertList.ItemsSource = _alerts;

        Refresh();
        EventBus.Instance.Subscribe(this);

        // Reflect the persisted mute state on the button once the tray has wired GetSettings (Loaded fires after Show).
        Loaded += (_, _) => RefreshMuteButton();

        // Periodic refresh so relative time labels stay accurate
        // 5s so harness tiles / stat counts feel live (the alert feed only rebuilds on change — see _lastAlertSig).
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _refreshTimer.Tick += (_, _) => Refresh();
        _refreshTimer.Start();

        // Resource usage is sampled on a background loop (GetProcessSnapshot is wired by the tray after
        // construction, so the provider reads it lazily each pass); the usage timer just pulls the latest
        // snapshot onto the UI thread — never running the slow GPU perf-counter enumeration on the dispatcher.
        _telemetry = new UiTelemetryCache(() =>
            GetProcessSnapshot?.Invoke()?.Select(p => p.Pid).ToList() ?? (IReadOnlyCollection<int>)[]);
        _usageTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _usageTimer.Tick += (_, _) => SampleUsage();
        _usageTimer.Start();

        SetPadlockVisual(Security.PresenceGuard.IsEnabled, animate: false);
        Activated += (_, _) => { if (!_padlockBusy) SetPadlockVisual(Security.PresenceGuard.IsEnabled, animate: false); };
    }

    // ── Presence padlock ─────────────────────────────────────────────────────
    private bool _padlockBusy;
    private static readonly System.Windows.Media.Color LockedColor =
        (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF3FB950");
    private static readonly System.Windows.Media.Color UnlockedColor =
        (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF8B949E");

    private void SetPadlockVisual(bool locked, bool animate)
    {
        PadlockLabel.Text = locked ? "Locked" : "Unlocked";
        PadlockLabel.Foreground = new System.Windows.Media.SolidColorBrush(locked ? LockedColor : UnlockedColor);
        var angle = locked ? 0.0 : -30.0;
        var color = locked ? LockedColor : UnlockedColor;

        if (!animate)
        {
            ShackleRotate.Angle = angle;
            LockBodyBrush.Color = color; ShackleBrush.Color = color;
            PadlockGlow.BlurRadius = 0; PadlockScale.ScaleX = PadlockScale.ScaleY = 1;
            return;
        }

        // shackle swings shut/open with a springy overshoot
        ShackleRotate.BeginAnimation(System.Windows.Media.RotateTransform.AngleProperty,
            new System.Windows.Media.Animation.DoubleAnimation(angle, TimeSpan.FromSeconds(0.55))
            { EasingFunction = new System.Windows.Media.Animation.BackEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut, Amplitude = 0.7 } });

        var recolor = new System.Windows.Media.Animation.ColorAnimation(color, TimeSpan.FromSeconds(0.45));
        LockBodyBrush.BeginAnimation(System.Windows.Media.SolidColorBrush.ColorProperty, recolor);
        ShackleBrush.BeginAnimation(System.Windows.Media.SolidColorBrush.ColorProperty, recolor.Clone());

        if (locked)
        {
            // satisfying snap + green glow pulse on arming
            var snap = new System.Windows.Media.Animation.DoubleAnimation
            {
                From = 1.22, To = 1.0, Duration = TimeSpan.FromSeconds(0.6),
                EasingFunction = new System.Windows.Media.Animation.ElasticEase
                { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut, Oscillations = 2, Springiness = 5 },
            };
            PadlockScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, snap);
            PadlockScale.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, snap.Clone());

            PadlockGlow.Color = LockedColor;
            PadlockGlow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.BlurRadiusProperty,
                new System.Windows.Media.Animation.DoubleAnimation { From = 20, To = 4, Duration = TimeSpan.FromSeconds(0.75),
                    EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut } });
        }
        else
        {
            PadlockGlow.BeginAnimation(System.Windows.Media.Effects.DropShadowEffect.BlurRadiusProperty,
                new System.Windows.Media.Animation.DoubleAnimation(0, TimeSpan.FromSeconds(0.3)));
        }
    }

    private async void PadlockClick(object sender, RoutedEventArgs e)
    {
        using var provenance = Security.SettingsChangeUiScope.Begin("change-presence-lock-dashboard");
        _padlockBusy = true;
        try
        {
            if (Security.PresenceGuard.IsEnabled)
            {
                var (ok, msg) = await Security.PresenceGuard.DisableAsync();
                if (ok) SetPadlockVisual(false, animate: true);
                else MessageBox.Show(msg, "TraceBrake — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!Security.PresenceGuard.IsAvailable)
            {
                MessageBox.Show("No authenticator available. Set up Windows Hello (a PIN or biometric) or attach a FIDO2 security key, then try again.",
                    "TraceBrake — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var choice = MessageBox.Show(
                "Require a Windows Hello or security-key tap to WEAKEN TraceBrake?\n\n" +
                "YES = Strict (also requires a tap to QUIT TraceBrake)\nNO = Standard (recommended)\nCancel = don't enable",
                "TraceBrake — Enable presence lock", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Cancel) return;
            var scope = choice == MessageBoxResult.Yes ? Foreman.Core.Security.LockScope.Strict : Foreman.Core.Security.LockScope.Standard;
            var (ok2, msg2) = await Security.PresenceGuard.EnableAsync(scope);
            if (ok2) SetPadlockVisual(true, animate: true);
            else MessageBox.Show(msg2, "TraceBrake — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally { _padlockBusy = false; }
    }

    // ── IEventSink ────────────────────────────────────────────────────────────

    void IEventSink.OnEvent(ForemanEvent evt)
    {
        // Info events (startup messages etc.) don't appear in the dashboard
        if (evt is InfoEvent) return;
        Dispatcher.BeginInvoke(Refresh);
    }

    // ── Data refresh ──────────────────────────────────────────────────────────

    private void Refresh()
    {
        // ── Alert feed ────────────────────────────────────────────────────────
        var history = EventBus.Instance.GetHistory();
        var relevant = history
            .Where(static e => e is CommandAlertEvent
                                  or EscalationEvent
                                  or HangDetectedEvent
                                  or OrphanDetectedEvent
                                  or MonitoringNoticeEvent)
            // Pin unresolved High/Critical items ahead of ordinary recency so a noise flood cannot push the
            // operator's most important outstanding evidence out of the 50-card overview.
            .OrderBy(e => !e.Acknowledged && e.Severity >= ForemanSeverity.High ? 0 : 1)
            .ThenByDescending(e => e.Timestamp)
            .Take(50)
            .ToList();

        // Only rebuild the feed when the event set actually changed — keeps the user's scroll position on the
        // now-5s refresh cadence (the cards/tiles below rebuild every tick; the feed shouldn't reset under them).
        var sig = relevant.Count == 0 ? "0" : $"{relevant.Count}:{relevant[0].Id}:{relevant[^1].Id}";
        if (sig != _lastAlertSig)
        {
            _lastAlertSig = sig;
            _alerts.Clear();
            foreach (var evt in relevant)
                _alerts.Add(DashboardAlertVm.From(evt));
        }

        var allProfiles = _getProfiles().ToList();
        var settings = GetSettings?.Invoke() ?? new ForemanSettings();
        var connectedClients = GetConnectedClients?.Invoke() ?? [];
        var recentlyConnected = new HashSet<string>(
            GetRecentlyConnectedHarnessIds?.Invoke() ?? [], StringComparer.OrdinalIgnoreCase);
        var snapshot = GetProcessSnapshot?.Invoke()?.ToList() ?? [];
        var wake = GetWakeRequests?.Invoke();
        var pendingTotal = GetPendingAskCount?.Invoke(null) ?? 0;

        // STICKY connection: a harness is "connected" if it has a live session (name-matched) OR made an
        // authenticated MCP request within the recent window. These clients hold no persistent session, so the
        // live list reads ~0 between calls — without this the cards flicker "restart to link" on working agents.
        bool Connected(string id) => recentlyConnected.Contains(id) || IsMcpConnected(connectedClients, id);

        // Per-harness MCP capability flags from the configured-server inventory: which agents are wired with a
        // computer-use (mouse/keyboard/screen) or browser-automation server.
        var inventory = GetMcpInventory?.Invoke() ?? [];
        var capByHarness = inventory
            .GroupBy(e => e.Harness, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => (
                    Computer: g.Where(McpCapabilityClassifier.IsComputerUse).Select(e => e.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                    Browser:  g.Where(McpCapabilityClassifier.IsBrowserUse).Select(e => e.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()),
                StringComparer.OrdinalIgnoreCase);
        (string[] Computer, string[] Browser) CapOf(string id) =>
            capByHarness.TryGetValue(id, out var c) ? c : (Array.Empty<string>(), Array.Empty<string>());
        static string HarnessName(string id) => KnownHarnesses.GetById(id)?.DisplayName ?? id;

        // Whether each harness is wired to TraceBrake — read from a background-refreshed cache (config-file reads,
        // esp. a multi-MB ~/.claude.json, must not run on the UI thread). Keeps configured agents visible when idle.
        EnsureConfiguredCacheFresh();
        var cfgSnapshot = _configuredCache;   // snapshot the reference; the bg task swaps the whole dict atomically
        bool Cfg(string id) => cfgSnapshot.TryGetValue(id, out var v) && v;

        var connectedCount = KnownHarnesses.All.Count(h => Connected(h.Id));
        var computerHarnesses = capByHarness.Where(kv => kv.Value.Computer.Length > 0).Select(kv => HarnessName(kv.Key)).ToArray();
        var browserHarnesses  = capByHarness.Where(kv => kv.Value.Browser.Length  > 0).Select(kv => HarnessName(kv.Key)).ToArray();

        MetaLightsPanel.ItemsSource = BuildMetaLights(
            settings, connectedClients, connectedCount, computerHarnesses, browserHarnesses, pendingTotal,
            // The browser extension authenticates as the "browser-extension" harness, so the same sticky
            // last-activity window that drives the agent cards tells us whether it's currently linked.
            Connected("browser-extension"),
            Connected("liveweave"));

        var runningIds = snapshot
            .Where(p => !string.IsNullOrEmpty(p.HarnessType))
            .Select(p => p.HarnessType!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var profileById = allProfiles.ToDictionary(p => p.HarnessId, StringComparer.OrdinalIgnoreCase);
        var wakeByHarness = wake is { Available: true }
            ? BuildWakeMap(snapshot, wake)
            : new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        var chipHarnesses = KnownHarnesses.All
            .Where(h => !settings.DisabledHarnesses.Contains(h.Id))
            .Select(h =>
            {
                var running = runningIds.Contains(h.Id);
                var connected = Connected(h.Id);
                var trust = settings.HarnessTrust.TryGetValue(h.Id, out var t) ? Math.Clamp(t, 1, 5) : 3;
                return new HarnessChipVm(h, profileById.GetValueOrDefault(h.Id), running, connected, trust, Cfg(h.Id));
            })
            .Where(c => c.IsRunning || c.McpConnected || c.AlertCount > 0 || c.Configured)
            .OrderByDescending(c => (int)c.EscalationLevel)
            .ThenByDescending(c => c.AlertCount)
            .ThenBy(c => c.DisplayName)
            .ToList();

        HarnessPanel.ItemsSource = chipHarnesses;

        HarnessOverviewPanel.ItemsSource = KnownHarnesses.All
            .Where(h => !settings.DisabledHarnesses.Contains(h.Id))
            .Select(h =>
            {
                var procs = GetProcessesByHarness?.Invoke(h.Id)?.ToList()
                            ?? snapshot.Where(p => string.Equals(p.HarnessType, h.Id, StringComparison.OrdinalIgnoreCase)).ToList();
                var usage = HarnessUsageAggregator.Aggregate(procs, _liveMetrics, GetNetRate);
                var pending = GetPendingAskCount?.Invoke(h.Id) ?? 0;
                wakeByHarness.TryGetValue(h.Id, out var wakeCount);
                var running = runningIds.Contains(h.Id);
                var connected = Connected(h.Id);
                var (computerSrvs, browserSrvs) = CapOf(h.Id);
                return new DashboardHarnessCardVm(
                    h,
                    profileById.GetValueOrDefault(h.Id),
                    running,
                    connected,
                    settings.HarnessTrust.TryGetValue(h.Id, out var trust2) ? Math.Clamp(trust2, 1, 5) : 3,
                    procs.Count,
                    usage,
                    pending,
                    wakeCount,
                    GetContextUsage?.Invoke(h.Id),
                    Cfg(h.Id),
                    computerSrvs,
                    browserSrvs);
            })
            // Show every harness that's running, MCP-connected, has alerts, is CONFIGURED for Foreman, or carries a
            // computer-use/browser capability — so your set-up agents (and their C/B chips) stay visible even when
            // idle. The card itself shows the live state ("MCP linked" / "restart to link" / "Configured · idle").
            .Where(c => c.IsRunning || c.McpConnected || c.AlertCount > 0 || c.Configured || c.ComputerUse || c.BrowserUse)
            .OrderByDescending(c => c.IsRunning)
            .ThenByDescending(c => (int)c.EscalationLevel)
            .ThenBy(c => c.DisplayName)
            .ToList();

        NoConnectedHarnessText.Visibility =
            ((IReadOnlyCollection<DashboardHarnessCardVm>)HarnessOverviewPanel.ItemsSource).Count == 0
                ? Visibility.Visible
                : Visibility.Collapsed;

        UpdateAgentUsageFootnote(snapshot);

        // ── Header summary ────────────────────────────────────────────────────
        // "Active alerts" = unacknowledged events ABOVE Info severity.
        var active = history
            .Where(AlertActivity.IsActive)   // the one shared definition (tray/dashboard/MCP agree)
            .ToList();

        SummaryLabel.Text = active.Count == 0
            ? "all clear"
            : $"{active.Count} active alert{(active.Count == 1 ? "" : "s")}";

        ActiveAlertCountLabel.Text = active.Count.ToString(CultureInfo.InvariantCulture);
        AckAllButton.Visibility = active.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        HarnessCountLabel.Text = (GetRunningAgentCount?.Invoke() ?? allProfiles.Count)
            .ToString(CultureInfo.InvariantCulture);
        HighAlertCountLabel.Text = active
            .Count(e => e.Severity >= ForemanSeverity.High)
            .ToString(CultureInfo.InvariantCulture);
        LastEventLabel.Text = relevant.FirstOrDefault() is { } last
            ? RelativeSummary(last.Timestamp)
            : "none";

        McpClientsLabel.Text = connectedCount.ToString(CultureInfo.InvariantCulture);
        NetCaptureLabel.Text = GetNetCaptureConnected?.Invoke() == true ? "On" : "Off";

        // Per-session capability breakdown on the MCP CLIENTS card (hover).
        McpClientsCard.ToolTip = connectedClients.Count == 0
            ? "No agents connected to TraceBrake's MCP.\nClick to open the Connect agent guide."
            : "Connected agents:\n" + string.Join("\n", connectedClients.Select(c =>
                $"  • {c.Name}{(string.IsNullOrWhiteSpace(c.Version) ? "" : $" v{c.Version}")} — " +
                $"sampling: {(c.Sampling ? "yes (Ask Harness gets a reply)" : "no (Ask Harness notifies one-way)")}"))
              + "\n\nClick to open the Connect agent guide.";

        // ── Footer ────────────────────────────────────────────────────────────
        var meta = $"TraceBrake v{Version}  ·  up {Uptime()}  ·  MCP :{McpPort}";
        FooterText.Text = relevant.Count == 0
            ? meta
            : $"{meta}  ·  {relevant.Count} recent event{(relevant.Count == 1 ? "" : "s")}  ·  click any row for detail";

        // ── Show / hide empty state ───────────────────────────────────────────
        var hasItems = relevant.Count > 0;
        EmptyPanel.Visibility = hasItems ? Visibility.Collapsed : Visibility.Visible;
        AlertList.Visibility  = hasItems ? Visibility.Visible   : Visibility.Collapsed;
    }

    // ── UI event handlers ─────────────────────────────────────────────────────

    private void AlertList_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        var item = FindAncestor<ListViewItem>(e.OriginalSource as DependencyObject);
        if (item?.DataContext is not DashboardAlertVm vm) return;

        OpenAlertDetail(vm);
        e.Handled = true;
    }

    private void AlertList_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key is not (Key.Enter or Key.Space)) return;
        if (AlertList.SelectedItem is not DashboardAlertVm vm) return;

        OpenAlertDetail(vm);
        e.Handled = true;
    }

    private void OpenAlertDetail(DashboardAlertVm vm)
    {
        AlertList.SelectedItem = null;
        AlertDetailWindow.ShowFor(vm.OriginalEvent, this);
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match) return match;
            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private void OpenSettingsClick(object sender, RoutedEventArgs e) =>
        OpenSettingsRequested?.Invoke();

    private void ConnectAgentClick(object sender, RoutedEventArgs e) =>
        OpenConnectAgentRequested?.Invoke();

    // Mute/unmute the yellow warning toasts. Reads current state from settings, flips it, persists via the tray.
    private void MuteWarningsClick(object sender, RoutedEventArgs e)
    {
        var muted = GetSettings?.Invoke() is { } s && !s.NotifyOnWarning;
        SetWarningsMuted?.Invoke(!muted);
        RefreshMuteButton();
    }

    private void RefreshMuteButton()
    {
        if (MuteWarningsButton is null) return;
        var muted = GetSettings?.Invoke() is { } s && !s.NotifyOnWarning;
        MuteWarningsButton.Content = muted ? "Unmute warnings" : "Mute warnings";
        MuteWarningsButton.ToolTip = muted
            ? "Warning (yellow) toasts are OFF. Alerts still log and show in the dashboard. Click to re-enable them."
            : "Mute warning (yellow) alert toasts so they don't spam. Alerts still log and show in the dashboard.";
    }

    // ── Metric tile clicks ────────────────────────────────────────────────────
    // Each tile deep-links to the most useful view for that number.

    private void ActiveAlertsTileClick(object sender, MouseButtonEventArgs e)
    {
        _logView?.SetMinimumSeverity(ForemanSeverity.Low);   // alerts, without Info noise
        ShowTab(DashboardTab.Log);
    }

    private void AgentsTileClick(object sender, MouseButtonEventArgs e) =>
        ShowTab(DashboardTab.Processes);

    private void HighCriticalTileClick(object sender, MouseButtonEventArgs e)
    {
        _logView?.SetMinimumSeverity(ForemanSeverity.High);
        ShowTab(DashboardTab.Log);
    }

    private void LastEventTileClick(object sender, MouseButtonEventArgs e)
    {
        if (_alerts.FirstOrDefault() is { } vm)
            AlertDetailWindow.ShowFor(vm.OriginalEvent, this);
    }

    private void McpClientsTileClick(object sender, MouseButtonEventArgs e) =>
        OpenConnectAgentRequested?.Invoke();

    private void NetworkTileClick(object sender, MouseButtonEventArgs e) =>
        OpenSettingsRequested?.Invoke();

    // Meta-light dots deep-link to the pertinent view (so a red dot like "Ask pending" isn't a dead end).
    // Routed by the light's Label so this doesn't depend on the VM carrying a target.
    private void MetaLightClick(object sender, MouseButtonEventArgs e)
    {
        if (FindDataContext<DashboardMetaLightVm>(e.OriginalSource) is not { } light) return;
        switch (light.Label)
        {
            case "Ask pending":  ShowTab(DashboardTab.Harnesses); break;   // act on the harness holding the prompt
            case "Event log":    ShowTab(DashboardTab.Log); break;
            case "Extension":
            case "MCP clients":  OpenConnectAgentRequested?.Invoke(); break;
            default:             OpenSettingsRequested?.Invoke(); break;    // Presence, Game mode, Sidecar, MCP scan
        }
        e.Handled = true;
    }

    private void HarnessChipClick(object sender, MouseButtonEventArgs e)
    {
        if (FindDataContext<HarnessChipVm>(e.OriginalSource) is { } chip)
            OpenHarnessDetail(chip.HarnessId);
        else
            ShowTab(DashboardTab.Harnesses);
    }

    private void HarnessOverviewClick(object sender, MouseButtonEventArgs e)
    {
        if (FindDataContext<DashboardHarnessCardVm>(e.OriginalSource) is { } card)
            OpenHarnessDetail(card.HarnessId);
        else
            ShowTab(DashboardTab.Harnesses);
    }

    // Clicking a harness opens the verbose detail view (live usage + behavior + MCP + processes).
    // "Harness settings" inside that window is the path to the editable trust/modality dialog.
    private void OpenHarnessDetail(string harnessId)
    {
        if (GetSettings is null) return;

        var ctx = new HarnessDetailContext
        {
            HarnessId = harnessId,
            GetProcesses = () => GetProcessesByHarness?.Invoke(harnessId)
                                 ?? (GetProcessSnapshot?.Invoke() ?? [])
                                     .Where(p => string.Equals(p.HarnessType, harnessId, StringComparison.OrdinalIgnoreCase)),
            GetProfile = () => _getProfiles().FirstOrDefault(p =>
                string.Equals(p.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase)),
            GetClients = () => GetConnectedClients?.Invoke() ?? [],
            GetSettings = () => GetSettings?.Invoke() ?? new ForemanSettings(),
            GetPendingAsk = () => GetPendingAskCount?.Invoke(harnessId) ?? 0,
            GetWakeLocks = () => WakeLocksFor(harnessId),
            GetNetRate = GetNetRate,
            OpenSettings = () => OpenHarnessSettings(harnessId),
            OpenConnectAgent = () => OpenConnectAgentRequested?.Invoke(),
            IsConfigured = () => _configuredCache.TryGetValue(harnessId, out var v) && v,
            GetContextUsage = () => GetContextUsage?.Invoke(harnessId),
            RequestCleanup = RequestHarnessCleanup is null ? null : () => RequestHarnessCleanup(harnessId),
            KillHarness = KillHarness is null ? null : () => KillHarness(harnessId),
            ResetMetrics = ResetBehaviorMetrics is null ? null : () => ResetBehaviorMetrics(harnessId),
        };

        new HarnessDetailWindow(ctx) { Owner = this }.Show();
    }

    private int WakeLocksFor(string harnessId)
    {
        var wake = GetWakeRequests?.Invoke();
        if (wake is not { Available: true }) return 0;
        var snapshot = GetProcessSnapshot?.Invoke()?.ToList() ?? [];
        return BuildWakeMap(snapshot, wake).GetValueOrDefault(harnessId);
    }

    private void OpenHarnessSettings(string harnessId)
    {
        var settings = GetSettings?.Invoke();
        if (settings is null) return;

        var display = KnownHarnesses.GetById(harnessId)?.DisplayName ?? harnessId;
        var w = new HarnessSettingsWindow(harnessId, display, settings, GetCuDriver, SetCuDriver, GetCuAttentionTab)
        { Owner = this };
        if (w.ShowDialog() == true)
            Refresh();
    }

    private void SampleUsage()
    {
        // Read the latest background sample (never null; empty until the first pass) and re-render.
        _liveMetrics = _telemetry.Latest;
        Refresh();
    }

    private void UpdateAgentUsageFootnote(IReadOnlyList<ProcessRecord> snapshot)
    {
        if (AgentUsageLabel is null) return;
        var harnessPids = snapshot.Where(p => p.IsHarness || !string.IsNullOrEmpty(p.HarnessType)).Select(p => p.Pid).ToList();
        if (harnessPids.Count == 0)
        {
            AgentUsageLabel.Text = string.Empty;
            return;
        }

        double cpu = 0;
        long mem = 0;
        foreach (var pid in harnessPids)
        {
            if (_liveMetrics.TryGetValue(pid, out var m))
            {
                cpu += m.CpuPercent;
                mem += m.MemoryBytes;
            }
        }

        AgentUsageLabel.Text = cpu > 0.5 || mem > 0
            ? $"Σ {HarnessUsageAggregator.FormatCpu(cpu)} CPU · {HarnessUsageAggregator.FormatMem(mem)} RAM"
            : string.Empty;
    }

    private IReadOnlyList<DashboardMetaLightVm> BuildMetaLights(
        ForemanSettings settings,
        IReadOnlyList<McpClientInfo> clients,
        int connectedCount,
        IReadOnlyList<string> computerHarnesses,
        IReadOnlyList<string> browserHarnesses,
        int pendingAsk,
        bool extConnected,
        bool liveweaveConnected)
    {
        var sidecarOn = GetNetCaptureConnected?.Invoke() == true;
        var gameOn = GetGameModeActive?.Invoke() == true && settings.GameMode.Enabled;
        var extPaired = settings.PairedExtensionOrigins.Count > 0;

        return
        [
            new DashboardMetaLightVm(
                "Presence",
                Security.PresenceGuard.IsEnabled ? MetaLightState.Ok : MetaLightState.Off,
                Security.PresenceGuard.IsEnabled
                    ? $"Presence lock armed ({Security.PresenceGuard.AuthenticatorLabel})."
                    : "Presence lock off — weakening actions need no tap."),
            new DashboardMetaLightVm(
                "Game mode",
                gameOn ? MetaLightState.Warn : MetaLightState.Off,
                gameOn
                    ? "Fullscreen detected — on-screen popups paused."
                    : settings.GameMode.Enabled ? "Game mode enabled, no fullscreen app detected." : "Game mode off."),
            // Three states: actively linked (the extension polled within the sticky window) > paired-but-idle
            // (allow-listed, but its side panel is closed so it isn't talking) > not paired. Mirrors the Sidecar
            // light's connected/configured-but-down/off pattern.
            new DashboardMetaLightVm(
                "Extension",
                extConnected ? MetaLightState.Ok
                    : extPaired ? MetaLightState.Warn : MetaLightState.Off,
                extConnected
                    ? "Browser LLM extension connected — linked and active."
                    : extPaired
                        ? $"Browser extension paired ({settings.PairedExtensionOrigins.Count} origin(s)) but idle — open its side panel in Chrome to connect."
                        : "Browser extension not paired — use Connect agent → Pair browser extension."),
            new DashboardMetaLightVm(
                "LiveWeave",
                liveweaveConnected ? MetaLightState.Ok
                    : extPaired ? MetaLightState.Warn : MetaLightState.Off,
                liveweaveConnected
                    ? "LiveWeave builder linked. Only the selected driver harness, or the operator token, can use liveweave_command."
                    : extPaired
                        ? "LiveWeave paired origin exists but extension is idle — open LiveWeave in Chrome."
                        : "LiveWeave not paired — pair LiveWeave extension via Connect agent → Pair browser extension."),
            new DashboardMetaLightVm(
                "Sidecar",
                sidecarOn ? MetaLightState.Ok
                    : settings.RunElevated ? MetaLightState.Warn : MetaLightState.Off,
                sidecarOn
                    ? "Elevated sidecar connected — network + wake telemetry live."
                    : settings.RunElevated
                        ? "Run elevated is on but the sidecar is not connected."
                        : "Elevated sidecar off (enable in Settings for network/wake columns)."),
            new DashboardMetaLightVm(
                "MCP scan",
                settings.ScanMcpTools ? MetaLightState.Warn : MetaLightState.Off,
                settings.ScanMcpTools
                    ? "Opt-in MCP tool-description scan is ON (outbound HTTP/SSE)."
                    : "MCP tool scan off."),
            new DashboardMetaLightVm(
                "Event log",
                settings.EventLogPersist ? MetaLightState.Ok : MetaLightState.Off,
                settings.EventLogPersist
                    ? "Event log persisted to disk (hash-chained JSONL)."
                    : "Event log is session-only."),
            new DashboardMetaLightVm(
                "Ask pending",
                pendingAsk > 0 ? MetaLightState.Alert : MetaLightState.Off,
                pendingAsk > 0
                    ? $"{pendingAsk} unanswered Ask Harness / audit prompt(s) waiting on a harness."
                    : "No pending Ask Harness requests."),
            new DashboardMetaLightVm(
                "Computer use",
                computerHarnesses.Count > 0 ? MetaLightState.Warn : MetaLightState.Off,
                computerHarnesses.Count > 0
                    ? $"Computer use (desktop control) available to: {string.Join(", ", computerHarnesses)}. " +
                      "These agents can move the mouse/keyboard and read the screen."
                    : "No monitored agent has a computer-use (desktop-control) MCP server configured.",
                glyph: "C"),
            new DashboardMetaLightVm(
                "Browser use",
                browserHarnesses.Count > 0 ? MetaLightState.Warn : MetaLightState.Off,
                browserHarnesses.Count > 0
                    ? $"Browser automation available to: {string.Join(", ", browserHarnesses)}. " +
                      "These agents can drive a real browser."
                    : "No monitored agent has a browser-automation MCP server configured.",
                glyph: "B"),
            new DashboardMetaLightVm(
                "MCP clients",
                connectedCount > 0 ? MetaLightState.Ok : MetaLightState.Off,
                connectedCount > 0
                    ? $"{connectedCount} agent(s) connected to TraceBrake's MCP (active within the last few minutes)."
                      + (clients.Count > 0
                            ? "\nLive now: " + string.Join(", ", clients.Select(c => c.Name))
                            : "")
                    : "No MCP clients connected."),
        ];
    }

    private static Dictionary<string, int> BuildWakeMap(IReadOnlyList<ProcessRecord> snapshot, WakeRequestSnapshot wake)
    {
        // PID reuse (and stale not-yet-pruned tree entries) means the snapshot can hold two records with the
        // same Pid — plain ToDictionary throws "same key already added" and crashes the whole refresh. Keep the
        // newest by start time.
        var byPid = snapshot.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.OrderByDescending(p => p.StartTime).First());
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var request in wake.Requests.Where(r => string.Equals(r.RequesterType, "PROCESS", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var process in snapshot.Where(p => MatchesWakeImage(p, request.Image)))
            {
                var harness = FindHarnessAncestor(byPid, process.Pid)?.HarnessType;
                if (string.IsNullOrWhiteSpace(harness)) continue;
                map[harness] = map.GetValueOrDefault(harness) + 1;
            }
        }
        return map;
    }

    private static bool MatchesWakeImage(ProcessRecord process, string image)
    {
        if (string.IsNullOrWhiteSpace(image)) return false;
        var name = Path.GetFileName(image.Replace('/', '\\'));
        return string.Equals(name, process.Name, StringComparison.OrdinalIgnoreCase)
               || (!string.IsNullOrWhiteSpace(process.ExecutablePath)
                   && string.Equals(Path.GetFileName(process.ExecutablePath), name, StringComparison.OrdinalIgnoreCase));
    }

    private static ProcessRecord? FindHarnessAncestor(IReadOnlyDictionary<int, ProcessRecord> byPid, int pid)
    {
        var seen = new HashSet<int>();
        while (byPid.TryGetValue(pid, out var current) && seen.Add(pid))
        {
            if (!string.IsNullOrWhiteSpace(current.HarnessType)) return current;
            if (current.ParentPid == 0 || current.ParentPid == current.Pid) break;
            pid = current.ParentPid;
        }
        return null;
    }

    private static bool IsMcpConnected(IReadOnlyList<McpClientInfo> clients, string harnessId) =>
        clients.Any(c => SseSessionManager.MatchesHarness(c.Name, null, harnessId));

    // Whether this harness's config already points at TraceBrake's MCP endpoint (so a "No MCP" running agent just
    // needs restarting to link, vs. one that was never connected). Cheap config-file read; callers gate it to
    // running, not-yet-connected harnesses so it runs for only a handful per refresh.
    private bool IsHarnessConfigured(string harnessId)
    {
        try
        {
            return HarnessConnectors.All
                .FirstOrDefault(c => string.Equals(c.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase))
                ?.IsConfigured(McpPort) ?? false;
        }
        catch { return false; }
    }

    // Recompute the "configured for Foreman" set off the UI thread, at most every 30s, and publish it to
    // _configuredCache. Each connector's IsConfigured reads (and parses) its agent's config file, and
    // ~/.claude.json can be many MB — doing that 16x on every 5s tick was the dashboard lag.
    private void EnsureConfiguredCacheFresh()
    {
        if (_configuredRefreshing) return;
        if (_configuredCache.Count > 0 && DateTimeOffset.UtcNow - _configuredCacheAt < TimeSpan.FromSeconds(30)) return;
        _configuredRefreshing = true;
        var ids = KnownHarnesses.All.Select(h => h.Id).ToArray();
        Task.Run(() =>
        {
            var map = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (var id in ids) map[id] = IsHarnessConfigured(id);   // reads config files; McpPort read is thread-safe
            return map;
        }).ContinueWith(t =>
        {
            if (t.Status == TaskStatus.RanToCompletion)
            {
                _configuredCache = t.Result;
                _configuredCacheAt = DateTimeOffset.UtcNow;
            }
            _configuredRefreshing = false;
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    private static T? FindDataContext<T>(object? source) where T : class
    {
        if (source is not DependencyObject d) return null;
        while (d is not null)
        {
            if (d is FrameworkElement { DataContext: T ctx }) return ctx;
            d = VisualTreeHelper.GetParent(d);
        }
        return null;
    }

    // Bulk acknowledge: events are shared instances across EventBus history, ForemanState,
    // and the views, so flipping Acknowledged here clears the tray, the MCP counts, and this
    // dashboard together. The InfoEvent is the audit trail (and pokes event-driven refreshes).
    private void AcknowledgeAllClick(object sender, RoutedEventArgs e)
    {
        var acked = 0;
        foreach (var evt in EventBus.Instance.GetHistory())
        {
            if (evt.Severity > ForemanSeverity.Info && !evt.Acknowledged)
            {
                evt.Acknowledged = true;
                acked++;
            }
        }

        if (acked > 0)
        {
            EventBus.Instance.Publish(new InfoEvent(
                DateTimeOffset.UtcNow, "Foreman.Dashboard",
                $"Operator acknowledged all alerts ({acked})."));
        }

        Refresh();
    }

    // ── Tabs / hosted views ───────────────────────────────────────────────────

    public enum DashboardTab { Overview = 0, Processes = 1, Harnesses = 2, Behavior = 3, Log = 4, Vault = 5, Approvals = 6, Setup = 7, Mutes = 8, Connect = 9, Settings = 10 }

    public void ShowTab(DashboardTab tab) => Tabs.SelectedIndex = (int)tab;

    /// <summary>Injects the monitoring views (built by the tray) into their tabs; disposed on close.</summary>
    public void HostViews(UIElement? processes, UIElement? harnesses, UIElement? behavior, UIElement? log,
                          UIElement? vault = null, UIElement? approvals = null, UIElement? setup = null,
                          UIElement? mutes = null, UIElement? connect = null, UIElement? settings = null)
    {
        ProcessSlot.Content   = processes;
        HarnessSlot.Content   = harnesses;
        BehaviorSlot.Content  = behavior;
        LogSlot.Content       = log;
        VaultSlot.Content     = vault;
        ApprovalsSlot.Content = approvals;
        SetupSlot.Content     = setup;
        MutesSlot.Content     = mutes;
        ConnectSlot.Content   = connect;
        SettingsSlot.Content  = settings;
        _harnessView   = harnesses as HarnessesWindow;   // for the unsaved-changes prompt on navigate-away
        _logView       = log as LogWindow;               // for tile deep-links with a pre-set severity filter
        _vaultView     = vault as VaultView;             // refreshed on tab-show so it reflects external lock/unlock
        _approvalsView = approvals as CuApprovalsView;   // refreshed on tab-show so it reflects the live held-action list
        _setupView     = setup as SetupHealthView;       // refreshed on tab-show so it reflects live service state
        _mutesView     = mutes as MutesView;             // refreshed on tab-show so it reflects mutes added/expired elsewhere
        _connectView   = connect as ConnectAgentView;    // refreshed on tab-show so the connected-agent list stays live
        _settingsView  = settings as SettingsView;        // refreshed on tab-show so it reflects settings changed elsewhere
        if (_harnessView is not null)
            _harnessView.OpenConnectAgent = () => OpenConnectAgentRequested?.Invoke();
        foreach (var v in new object?[] { processes, harnesses, behavior, log, vault, approvals, setup, mutes, connect, settings })
            if (v is IDisposable d) _hostedViews.Add(d);
    }

    // Prompt to save Harnesses-tab edits when the user navigates away (switches tab) or closes.
    private async void TabsSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // TabControl SelectionChanged bubbles from child ListViews too — only react to the tabs themselves.
        if (!ReferenceEquals(e.OriginalSource, Tabs)) return;
        // Refresh the Vault/Approvals/Setup views whenever their tab is shown, so they reflect changes done elsewhere.
        if (e.AddedItems.Count > 0 && e.AddedItems[0] is TabItem vt)
        {
            if (Tabs.Items.IndexOf(vt) == (int)DashboardTab.Vault) _vaultView?.RefreshState();
            if (Tabs.Items.IndexOf(vt) == (int)DashboardTab.Approvals) _approvalsView?.RefreshState();
            if (Tabs.Items.IndexOf(vt) == (int)DashboardTab.Setup) _setupView?.RefreshState();
            if (Tabs.Items.IndexOf(vt) == (int)DashboardTab.Mutes) _mutesView?.RefreshState();
            if (Tabs.Items.IndexOf(vt) == (int)DashboardTab.Connect) _connectView?.RefreshState();
        }
        if (_harnessView is null || e.RemovedItems.Count == 0) return;
        if (e.RemovedItems[0] is not TabItem leftTab) return;
        if (Tabs.Items.IndexOf(leftTab) != (int)DashboardTab.Harnesses) return;
        if (!_harnessView.HasUnsavedChanges()) return;

        switch (PromptSaveHarnesses("switching tabs"))
        {
            case MessageBoxResult.Yes:
                if (!await _harnessView.SaveChanges())                  // denied → reverted; snap back to Harnesses tab
                    _ = Dispatcher.BeginInvoke(() => Tabs.SelectedItem = leftTab);   // fire-and-forget UI re-select
                break;
            case MessageBoxResult.No:     _harnessView.Revert();      break;
            case MessageBoxResult.Cancel:
                // Re-select the Harnesses tab once this event settles.
                _ = Dispatcher.BeginInvoke(() => Tabs.SelectedItem = leftTab);   // fire-and-forget UI re-select
                break;
        }
    }

    private bool _forceClose;

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (!_forceClose && _harnessView?.HasUnsavedChanges() == true)
        {
            switch (PromptSaveHarnesses("closing"))
            {
                case MessageBoxResult.Yes:
                    e.Cancel = true;                 // hold the close until the gated save resolves, then re-close
                    _ = SaveThenCloseAsync();
                    return;
                case MessageBoxResult.No:     break;                       // discard, allow close
                case MessageBoxResult.Cancel: e.Cancel = true; return;     // stay open
            }
        }
        base.OnClosing(e);
    }

    // Await the gated save (deny reverts, never persists), then close for real — so a denied tap can't be
    // outraced by the window closing first (the adversarial-review fix).
    private async Task SaveThenCloseAsync()
    {
        await _harnessView!.SaveChanges();
        _forceClose = true;
        Close();
    }

    private static MessageBoxResult PromptSaveHarnesses(string action) =>
        MessageBox.Show(
            $"You have unsaved changes on the Harnesses tab.\n\nSave them before {action}?",
            "TraceBrake — Unsaved changes", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

    private static string Version =>
        System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1";

    private static string Uptime()
    {
        try
        {
            var up = DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime;
            if (up.TotalMinutes < 1) return "<1m";
            if (up.TotalHours   < 1) return $"{(int)up.TotalMinutes}m";
            if (up.TotalDays    < 1) return $"{(int)up.TotalHours}h {up.Minutes:D2}m";
            return $"{(int)up.TotalDays}d {up.Hours}h";
        }
        catch { return "?"; }
    }

    protected override void OnClosed(EventArgs e)
    {
        EventBus.Instance.Unsubscribe(this);
        _refreshTimer.Stop();
        _usageTimer.Stop();
        _telemetry.Dispose();
        foreach (var d in _hostedViews) { try { d.Dispose(); } catch { /* best-effort */ } }
        _hostedViews.Clear();
        base.OnClosed(e);
    }

    private static string RelativeSummary(DateTimeOffset ts)
    {
        var ago = DateTimeOffset.UtcNow - ts;
        if (ago.TotalSeconds < 30) return "just now";
        if (ago.TotalMinutes < 60) return $"{Math.Max(1, (int)ago.TotalMinutes)}m ago";
        if (ago.TotalHours < 24) return $"{(int)ago.TotalHours}h ago";
        return $"{(int)ago.TotalDays}d ago";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DashboardAlertVm — one row in the alert feed
// ─────────────────────────────────────────────────────────────────────────────

public sealed class DashboardAlertVm
{
    public string     SeverityLabel     { get; }
    public Brush      SeverityBrush     { get; }
    public string     TagBadge          { get; }  // "NET", "CRED", "ESC", "HANG" …
    public Brush      TagBg             { get; }
    public Brush      TagFg             { get; }
    public string     Headline          { get; }  // primary display text
    public string     SubLine           { get; }  // command / categories / detail
    public Visibility SubLineVisibility { get; }
    public string     TimeAgo           { get; }
    public ForemanEvent OriginalEvent   { get; }

    private DashboardAlertVm(
        string severityLabel, Brush severityBrush,
        string tagBadge, Brush tagBg, Brush tagFg,
        string headline, string subLine, string timeAgo,
        ForemanEvent originalEvent)
    {
        SeverityLabel     = severityLabel;
        SeverityBrush     = severityBrush;
        TagBadge          = tagBadge;
        TagBg             = tagBg;
        TagFg             = tagFg;
        Headline          = headline;
        SubLine           = subLine;
        SubLineVisibility = string.IsNullOrEmpty(subLine) ? Visibility.Collapsed : Visibility.Visible;
        TimeAgo           = timeAgo;
        OriginalEvent     = originalEvent;
    }

    public static DashboardAlertVm From(ForemanEvent evt)
    {
        var (tag, tagBg, tagFg) = GetTag(evt);
        var (headline, subLine) = GetContent(evt);

        return new DashboardAlertVm(
            evt.Severity.ToString().ToUpperInvariant(),
            SeverityToBrush(evt.Severity),
            tag, tagBg, tagFg,
            headline, subLine,
            RelativeTime(evt.Timestamp),
            evt);
    }

    // ── Tag badge ─────────────────────────────────────────────────────────────

    private static (string tag, Brush bg, Brush fg) GetTag(ForemanEvent evt) => evt switch
    {
        CommandAlertEvent cmd => CommandTag(cmd.RuleId),

        EscalationEvent esc => esc.NewLevel switch
        {
            EscalationLevel.Emergency => ("ESC",
                new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
                new SolidColorBrush(Color.FromRgb(0xFF, 0x77, 0x77))),
            EscalationLevel.Alarm => ("ESC",
                new SolidColorBrush(Color.FromRgb(0x3A, 0x1A, 0x04)),
                new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x55))),
            _ => ("ESC",
                new SolidColorBrush(Color.FromRgb(0x2C, 0x22, 0x06)),
                new SolidColorBrush(Color.FromRgb(0xE8, 0xC0, 0x55))),
        },

        HangDetectedEvent => ("HANG",
            new SolidColorBrush(Color.FromRgb(0x1C, 0x18, 0x06)),
            new SolidColorBrush(Color.FromRgb(0xCC, 0xAA, 0x44))),

        OrphanDetectedEvent => ("ORPHAN",
            new SolidColorBrush(Color.FromRgb(0x18, 0x14, 0x04)),
            new SolidColorBrush(Color.FromRgb(0xAA, 0x88, 0x33))),

        _ => ("EVENT",
            new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x24)),
            new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };

    private static (string tag, Brush bg, Brush fg) CommandTag(string ruleId)
    {
        var cat = ruleId.Split('-')[0].ToUpperInvariant();
        return cat switch
        {
            "CRED" => (cat,
                new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
                new SolidColorBrush(Color.FromRgb(0xFF, 0x88, 0x88))),
            "NET" => (cat,
                new SolidColorBrush(Color.FromRgb(0x0A, 0x1C, 0x38)),
                new SolidColorBrush(Color.FromRgb(0x66, 0xAA, 0xFF))),
            "PRIV" => (cat,
                new SolidColorBrush(Color.FromRgb(0x28, 0x0A, 0x2C)),
                new SolidColorBrush(Color.FromRgb(0xCC, 0x77, 0xFF))),
            "WIN" => (cat,
                new SolidColorBrush(Color.FromRgb(0x10, 0x14, 0x34)),
                new SolidColorBrush(Color.FromRgb(0x88, 0x99, 0xFF))),
            "DEL" => (cat,
                new SolidColorBrush(Color.FromRgb(0x2E, 0x1E, 0x04)),
                new SolidColorBrush(Color.FromRgb(0xEE, 0xCC, 0x44))),
            _ => (cat,
                new SolidColorBrush(Color.FromRgb(0x18, 0x1A, 0x22)),
                new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
        };
    }

    // ── Headline + subLine ────────────────────────────────────────────────────

    private static (string headline, string subLine) GetContent(ForemanEvent evt) => evt switch
    {
        CommandAlertEvent cmd =>
            (
                $"{cmd.RuleName}  ·  {ProcessName(cmd.Source)}",
                cmd.CommandLine.Length > 120
                    ? cmd.CommandLine[..120] + "…"
                    : cmd.CommandLine
            ),

        EscalationEvent esc =>
            (
                $"{esc.HarnessDisplayName}  →  {esc.NewLevel.ToString().ToUpperInvariant()}",
                BuildEscSubLine(esc)
            ),

        HangDetectedEvent hang =>
            (
                $"{hang.ProcessName}  (pid {hang.ProcessId})  -  no I/O for {hang.SilentMinutes}min",
                $"{HangOwnerLine(hang)}  -  running {hang.UptimeMinutes}min total"
            ),

        OrphanDetectedEvent orphan =>
            (
                $"{orphan.ProcessName}  —  orphaned after parent exited",
                $"was child of {orphan.DeadParentName} (pid {orphan.DeadParentPid})" +
                $"  ·  running {orphan.UptimeMinutes}min"
            ),

        _ => (
            evt.Message.Length > 100 ? evt.Message[..100] + "…" : evt.Message,
            string.Empty
        ),
    };

    private static string BuildEscSubLine(EscalationEvent esc)
    {
        var parts = new List<string>
        {
            $"{esc.TotalAlerts} alert{(esc.TotalAlerts == 1 ? "" : "s")}",
        };
        if (esc.UniqueRules > 0)
            parts.Add($"{esc.UniqueRules} rule{(esc.UniqueRules == 1 ? "" : "s")}");
        if (esc.CategoryList.Length > 0)
            parts.Add(string.Join(", ", esc.CategoryList).ToUpperInvariant());
        return string.Join("  ·  ", parts);
    }

    private static string HangOwnerLine(HangDetectedEvent hang)
    {
        var parts = new List<string>();

        if (hang.SpawnerPid is int spawnerPid)
        {
            if (hang.ParentHarnessPid == spawnerPid && !string.IsNullOrWhiteSpace(hang.ParentHarnessType))
            {
                parts.Add(string.IsNullOrWhiteSpace(hang.SpawnerName)
                    ? $"spawned by {hang.ParentHarnessType} pid {spawnerPid}"
                    : $"spawned by {hang.ParentHarnessType} ({hang.SpawnerName}, pid {spawnerPid})");
            }
            else
            {
                parts.Add(string.IsNullOrWhiteSpace(hang.SpawnerName)
                    ? $"spawned by pid {spawnerPid}"
                    : $"spawned by {hang.SpawnerName} (pid {spawnerPid})");
            }
        }

        if (hang.ParentHarnessPid is int ownerPid && ownerPid != hang.SpawnerPid)
        {
            var type = string.IsNullOrWhiteSpace(hang.ParentHarnessType)
                ? "harness"
                : hang.ParentHarnessType;
            var owner = string.IsNullOrWhiteSpace(hang.ParentHarnessName)
                ? $"{type} pid {ownerPid}"
                : $"{type} ({hang.ParentHarnessName}, pid {ownerPid})";
            parts.Add($"owned by {owner}");
        }

        return parts.Count == 0 ? "owner unknown" : string.Join(" - ", parts);
    }

    private static string ProcessName(string source)
    {
        // Source format: "processName (pid 12345)"
        var idx = source.IndexOf(" (pid", StringComparison.Ordinal);
        return idx > 0 ? source[..idx] : source;
    }

    // ── Severity brush ────────────────────────────────────────────────────────

    private static Brush SeverityToBrush(ForemanSeverity s) => s switch
    {
        ForemanSeverity.Critical => new SolidColorBrush(Color.FromRgb(0xCC, 0x22, 0x22)),
        ForemanSeverity.High     => new SolidColorBrush(Color.FromRgb(0xCC, 0x55, 0x22)),
        ForemanSeverity.Medium   => new SolidColorBrush(Color.FromRgb(0xAA, 0x77, 0x11)),
        ForemanSeverity.Low      => new SolidColorBrush(Color.FromRgb(0x33, 0x77, 0x33)),
        _                        => new SolidColorBrush(Color.FromRgb(0x33, 0x66, 0x99)),
    };

    // ── Relative time ─────────────────────────────────────────────────────────

    private static string RelativeTime(DateTimeOffset ts)
    {
        var ago = DateTimeOffset.UtcNow - ts;
        if (ago.TotalSeconds < 30) return "just now";
        if (ago.TotalMinutes <  2) return $"{(int)ago.TotalSeconds}s ago";
        if (ago.TotalMinutes < 60) return $"{(int)ago.TotalMinutes}m ago";
        if (ago.TotalHours   < 24) return $"{(int)ago.TotalHours}h ago";
        return $"{(int)ago.TotalDays}d ago";
    }
}

// HarnessChipVm — compact header chip for active harnesses
// ─────────────────────────────────────────────────────────────────────────────

public sealed class HarnessChipVm
{
    public string HarnessId { get; }
    public string DisplayName { get; }
    public string LevelLabel { get; }
    public Brush LevelBg { get; }
    public Brush LevelFg { get; }
    public string TrustLabel { get; }
    public string McpLabel { get; }
    public string ToolTip { get; }
    public bool IsRunning { get; }
    public bool McpConnected { get; }
    public bool Configured { get; }
    public int AlertCount { get; }
    public EscalationLevel EscalationLevel { get; }

    public HarnessChipVm(KnownHarness harness, BehaviorProfile? profile, bool isRunning, bool mcpConnected, int trust, bool configured = false)
    {
        Configured = configured;
        HarnessId = harness.Id;
        DisplayName = harness.DisplayName;
        IsRunning = isRunning;
        McpConnected = mcpConnected;
        AlertCount = profile?.TotalAlerts ?? 0;
        EscalationLevel = profile?.CurrentLevel ?? EscalationLevel.Watch;
        LevelLabel = EscalationLevel.ToString().ToUpperInvariant();
        TrustLabel = $"  ·  T{trust}";
        McpLabel = mcpConnected ? "  ·  MCP" : (isRunning && configured) ? "  ·  Ready" : string.Empty;
        (LevelBg, LevelFg) = EscalationColors(EscalationLevel);
        ToolTip = BuildToolTip(harness.DisplayName, isRunning, mcpConnected, configured, trust, AlertCount, EscalationLevel);
    }

    private static (Brush bg, Brush fg) EscalationColors(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => (
            new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))),
        EscalationLevel.Alarm => (
            new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x44))),
        EscalationLevel.Alert => (
            new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
        _ => (
            new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x28)),
            new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };

    private static string BuildToolTip(string name, bool running, bool mcp, bool configured, int trust, int alerts, EscalationLevel level) =>
        $"{name}\n{(running ? "Running" : "Not running")} · Trust {trust} · {level}\n" +
        $"{alerts} alert{(alerts == 1 ? "" : "s")}" +
        (mcp ? " · MCP connected"
             : (running && configured) ? " · MCP configured — links automatically the next time it calls a TraceBrake tool (no restart needed)"
             : configured ? " · MCP configured (idle — start it to connect)"
             : " · MCP not connected") +
        "\nClick for live detail.";
}

// ─────────────────────────────────────────────────────────────────────────────
// DashboardHarnessCardVm — overview tab card per harness
// ─────────────────────────────────────────────────────────────────────────────

public sealed class DashboardHarnessCardVm
{
    public string HarnessId { get; }
    public string DisplayName { get; }
    public string Subtitle { get; }
    public string StatusText { get; }
    public Brush StatusBackground { get; }
    public Brush StatusForeground { get; }
    public string TrustLabel { get; }
    public string EscalationLabel { get; }
    public Brush EscalationForeground { get; }
    public string DetailLine { get; }
    public Brush DetailForeground { get; }
    public Brush BorderBrush { get; }
    public string ToolTip { get; }
    public bool IsRunning { get; }
    public bool McpConnected { get; }
    public int AlertCount { get; }
    public EscalationLevel EscalationLevel { get; }
    public IReadOnlyList<HarnessLightVm> Lights { get; }

    public bool Configured { get; }

    // Capability flags — does this agent have a computer-use / browser-automation MCP server configured?
    public bool ComputerUse { get; }
    public bool BrowserUse { get; }
    public string ComputerUseTip { get; }
    public string BrowserUseTip { get; }
    public Visibility ComputerUseVisibility => ComputerUse ? Visibility.Visible : Visibility.Collapsed;
    public Visibility BrowserUseVisibility => BrowserUse ? Visibility.Visible : Visibility.Collapsed;

    public DashboardHarnessCardVm(
        KnownHarness harness,
        BehaviorProfile? profile,
        bool isRunning,
        bool mcpConnected,
        int trust,
        int processCount,
        HarnessUsage usage,
        int pendingAsk,
        int wakeLocks,
        HarnessContextUsage? contextUsage = null,
        bool configured = false,
        string[]? computerUseServers = null,
        string[]? browserUseServers = null)
    {
        Configured = configured;
        var cuse = computerUseServers ?? [];
        var buse = browserUseServers ?? [];
        ComputerUse = cuse.Length > 0;
        BrowserUse = buse.Length > 0;
        ComputerUseTip = ComputerUse
            ? $"Computer use ENABLED — {harness.DisplayName} has a desktop-control MCP server ({string.Join(", ", cuse)}). It can move the mouse/keyboard and read the screen."
            : "No computer-use (desktop-control) MCP server configured for this agent.";
        BrowserUseTip = BrowserUse
            ? $"Browser use ENABLED — {harness.DisplayName} has a browser-automation MCP server ({string.Join(", ", buse)}). It can drive a real browser."
            : "No browser-automation MCP server configured for this agent.";
        HarnessId = harness.Id;
        DisplayName = harness.DisplayName;
        IsRunning = isRunning;
        McpConnected = mcpConnected;
        EscalationLevel = profile?.CurrentLevel ?? EscalationLevel.Watch;
        Subtitle = harness.Developer;

        StatusText = isRunning ? "Running" : "Idle";
        StatusBackground = isRunning
            ? new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x1A))
            : new SolidColorBrush(Color.FromRgb(0x1E, 0x20, 0x28));
        StatusForeground = isRunning
            ? new SolidColorBrush(Color.FromRgb(0x7E, 0xC8, 0x78))
            : new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90));

        TrustLabel = $"Trust {trust}";
        EscalationLabel = EscalationLevel.ToString().ToUpperInvariant();
        EscalationForeground = EscalationColors(EscalationLevel).fg;

        var alerts = profile?.TotalAlerts ?? 0;
        AlertCount = alerts;
        var pa = $"{processCount} proc{(processCount == 1 ? "" : "s")} · {alerts} alert{(alerts == 1 ? "" : "s")}";
        var muted = new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90));
        string detail;
        Brush detailFg = muted;
        if (mcpConnected)
        {
            detail = $"MCP linked · {pa}";
        }
        else if (isRunning && configured)
        {
            // TraceBrake is in this agent's config with a valid token; the agent just hasn't called a TraceBrake tool
            // yet. MCP clients connect lazily (on first tool use), so it links automatically when it next does —
            // restarting does NOT help. (amber = the ball is in the agent's court, not TraceBrake's.)
            detail = $"Configured · Ready · {pa}";
            detailFg = new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C));
        }
        else if (isRunning)
        {
            detail = $"No MCP · {pa}";
        }
        else if (alerts > 0)
        {
            detail = $"{alerts} alert{(alerts == 1 ? "" : "s")} · not running";
        }
        else if (configured)
        {
            // Wired to TraceBrake but idle — shown so you can see it's set up; it links when you next start it.
            detail = "Configured · idle — start it to connect";
        }
        else
        {
            detail = "Not running · connect MCP for Ask Harness";
        }
        // Append the agent's self-reported context budget (via report_usage), when it has reported one.
        DetailLine = contextUsage?.ShortLabel is { } ctx ? $"{detail} · {ctx}" : detail;
        DetailForeground = detailFg;

        BorderBrush = EscalationLevel >= EscalationLevel.Alarm
            ? new SolidColorBrush(Color.FromRgb(0x66, 0x33, 0x11))
            : mcpConnected
                ? new SolidColorBrush(Color.FromRgb(0x2A, 0x4A, 0x2A))
                : new SolidColorBrush(Color.FromRgb(0x2A, 0x2F, 0x37));

        Lights = BuildLights(isRunning, mcpConnected, usage, pendingAsk, wakeLocks, EscalationLevel);
        ToolTip = $"{harness.DisplayName} ({harness.Id})\n{DetailLine}\n{DescribeLights(Lights)}\nClick for live detail.";
    }

    private static IReadOnlyList<HarnessLightVm> BuildLights(
        bool running, bool mcp, HarnessUsage usage, int pendingAsk, int wakeLocks, EscalationLevel esc)
    {
        var lights = new List<HarnessLightVm>
        {
            new(running ? MetaLightState.Ok : MetaLightState.Off,
                running ? "Process tree active" : "Not running"),
            new(mcp ? MetaLightState.Ok : MetaLightState.Off,
                mcp ? "MCP session linked" : "No MCP connection"),
        };

        if (esc >= EscalationLevel.Alert)
            lights.Add(new(esc >= EscalationLevel.Alarm ? MetaLightState.Alert : MetaLightState.Warn,
                $"Escalation: {esc}"));

        if (pendingAsk > 0)
            lights.Add(new(MetaLightState.Alert, $"{pendingAsk} pending Ask Harness prompt(s)"));

        if (wakeLocks > 0)
            lights.Add(new(MetaLightState.Warn, $"{wakeLocks} wake lock(s) attributed"));

        if (usage.CpuPercent >= 5)
            lights.Add(new(MetaLightState.Warn, $"CPU {HarnessUsageAggregator.FormatCpu(usage.CpuPercent)} (tree)"));

        if (usage.MemoryBytes >= 512L * 1024 * 1024)
            lights.Add(new(MetaLightState.Ok, $"RAM {HarnessUsageAggregator.FormatMem(usage.MemoryBytes)} (tree)"));

        if (usage.GpuPercent is >= 5)
            lights.Add(new(MetaLightState.Warn, $"GPU {usage.GpuPercent:0}% (peak)"));

        if (usage.NetBytesPerSec is > 1024)
            lights.Add(new(MetaLightState.Ok, $"Net {HarnessUsageAggregator.FormatRate(usage.NetBytesPerSec.Value)} (tree)"));

        if (usage.IoBytesPerSec > 256 * 1024)
            lights.Add(new(MetaLightState.Ok, $"I/O {HarnessUsageAggregator.FormatRate(usage.IoBytesPerSec)} (tree)"));

        return lights;
    }

    private static string DescribeLights(IReadOnlyList<HarnessLightVm> lights) =>
        string.Join("\n", lights.Select(l => l.ToolTip));

    private static (Brush bg, Brush fg) EscalationColors(EscalationLevel level) => level switch
    {
        EscalationLevel.Emergency => (
            new SolidColorBrush(Color.FromRgb(0x44, 0x0A, 0x0A)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))),
        EscalationLevel.Alarm => (
            new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xFF, 0xAA, 0x44))),
        EscalationLevel.Alert => (
            new SolidColorBrush(Color.FromRgb(0x30, 0x28, 0x08)),
            new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C))),
        _ => (
            new SolidColorBrush(Color.FromRgb(0x1A, 0x1C, 0x28)),
            new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))),
    };
}
