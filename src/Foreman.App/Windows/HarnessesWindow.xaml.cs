using Foreman.App.Security;
using Foreman.Core.Models;
using Foreman.Core.Power;
using Foreman.Core.Settings;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Foreman.App.Windows;

public partial class HarnessesWindow : UserControl
{
    private readonly ForemanSettings _settings;
    private readonly Func<IEnumerable<ProcessRecord>> _getSnapshot;
    private readonly Func<WakeRequestSnapshot>? _getWakeRequests;
    private readonly List<HarnessVm> _items = [];
    private readonly DispatcherTimer _liveTimer;

    /// <summary>Opens the Connect-Agent guide. Set by the hosting DashboardWindow.</summary>
    public Action? OpenConnectAgent { get; set; }

    /// <summary>Read / set the global computer-use driver (operator-only). Wired by the hosting TrayController to the
    /// CuBroker so the per-harness settings popup can authorize a harness past the "no CU driver selected" gate.</summary>
    public Func<string?>? GetCuDriver { get; set; }
    public Func<string?, Task<(bool Ok, string Reason)>>? SetCuDriver { get; set; }
    public Func<string?>? GetCuAttentionTab { get; set; }

    public HarnessesWindow(
        ForemanSettings settings,
        Func<IEnumerable<ProcessRecord>> getSnapshot,
        Func<WakeRequestSnapshot>? getWakeRequests = null)
    {
        _settings = settings;
        _getSnapshot = getSnapshot;
        _getWakeRequests = getWakeRequests;
        InitializeComponent();
        _liveTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _liveTimer.Tick += (_, _) => RefreshLiveState();
        Loaded += (_, _) => { Refresh(); _liveTimer.Start(); };
        Unloaded += (_, _) => _liveTimer.Stop();
    }

    // Last wake-lock probe result, reused on the synchronous (fast) refresh path so cards don't flicker to
    // "Wake n/a" between async probes.
    private WakeRequestSnapshot? _lastWake;
    private bool _wakeProbeInFlight;

    private void Refresh()
    {
        var snapshot = _getSnapshot().ToList();
        var live = BuildLiveState(snapshot, _lastWake);   // running state now; wake overlays asynchronously

        _items.Clear();

        // built-in harnesses
        foreach (var h in KnownHarnesses.All)
            _items.Add(new HarnessVm(h.Id, h.DisplayName, h.Developer, h.Description, isCustom: false, _settings, live));

        // user-added custom exes
        foreach (var exe in _settings.CustomHarnessExes)
        {
            var id = $"custom:{exe.ToLowerInvariant()}";
            _items.Add(new HarnessVm(id, exe, "Custom", $"Custom monitored process: {exe}", isCustom: true, _settings, live));
        }

        HarnessList.ItemsSource = null;
        HarnessList.ItemsSource = _items;

        FetchWakeAsync();   // wake probe shells out to powercfg/the sidecar — never block the UI thread on it
    }

    private void RefreshLiveState()
    {
        var snapshot = _getSnapshot().ToList();
        var live = BuildLiveState(snapshot, _lastWake);   // running state is cheap + synchronous
        foreach (var item in _items)
            item.UpdateLive(live);
        FetchWakeAsync();
    }

    // The wake-lock probe runs `powercfg /requests` via the elevated sidecar — a blocking call (it was run on the
    // UI thread on load + every 5s, which froze the Harnesses tab and left it blank). Run it off-thread and overlay
    // the result when it returns; only one probe in flight at a time so the timer can't pile them up.
    private void FetchWakeAsync()
    {
        var probe = _getWakeRequests;
        if (probe is null || _wakeProbeInFlight) return;
        _wakeProbeInFlight = true;
        var snapshot = _getSnapshot().ToList();   // captured on the UI thread (in-process, cheap)
        Task.Run<WakeRequestSnapshot?>(() => { try { return probe(); } catch { return null; } })
            .ContinueWith(t =>
            {
                _wakeProbeInFlight = false;
                if (t.Status != TaskStatus.RanToCompletion || t.Result is null) return;
                _lastWake = t.Result;
                var live = BuildLiveState(snapshot, _lastWake);
                foreach (var item in _items)
                    item.UpdateLive(live);
            }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    private HarnessLiveState BuildLiveState(IReadOnlyList<ProcessRecord> snapshot, WakeRequestSnapshot? wake)
    {
        var running = snapshot
            .Where(r => r.HarnessType is not null)
            .Select(r => r.HarnessType!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var w = BuildWakeByHarness(snapshot, wake);
        return new HarnessLiveState(running, w.Available, w.ByHarness, w.Error);
    }

    private static WakeByHarness BuildWakeByHarness(
        IReadOnlyList<ProcessRecord> snapshot,
        WakeRequestSnapshot? wake)
    {
        if (wake is null || !wake.Available)
            return new WakeByHarness(false, new(StringComparer.OrdinalIgnoreCase), wake?.Error);

        // PID reuse / stale tree entries can yield two records with the same Pid; plain ToDictionary throws and
        // crashes the refresh. Keep the newest by start time.
        var byPid = snapshot.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.OrderByDescending(p => p.StartTime).First());
        var byHarness = new Dictionary<string, List<WakeRequestEntry>>(StringComparer.OrdinalIgnoreCase);

        foreach (var request in wake.Requests.Where(r => IsProcessRequester(r.RequesterType)))
        {
            foreach (var process in snapshot.Where(p => MatchesWakeRequester(p, request.Image)))
            {
                var harness = FindHarnessAncestor(byPid, process.Pid)?.HarnessType;
                if (string.IsNullOrWhiteSpace(harness)) continue;
                if (!byHarness.TryGetValue(harness, out var list))
                    byHarness[harness] = list = [];
                if (!list.Contains(request))
                    list.Add(request);
            }
        }

        return new WakeByHarness(true, byHarness, null);
    }

    private static bool IsProcessRequester(string requesterType) =>
        string.Equals(requesterType, "PROCESS", StringComparison.OrdinalIgnoreCase);

    private static bool MatchesWakeRequester(ProcessRecord process, string requester)
    {
        if (string.IsNullOrWhiteSpace(requester)) return false;
        var requestName = SafeFileName(requester);
        if (!string.IsNullOrWhiteSpace(requestName) &&
            (string.Equals(requestName, process.Name, StringComparison.OrdinalIgnoreCase) ||
             string.Equals(requestName, SafeFileName(process.ExecutablePath), StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(process.ExecutablePath) &&
               string.Equals(NormalizePath(process.ExecutablePath), NormalizePath(requester), StringComparison.OrdinalIgnoreCase);
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

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path.Replace('/', '\\')); }
        catch { return path; }
    }

    private static string NormalizePath(string path) =>
        path.Trim().Replace('/', '\\');

    // ── Add custom exe ────────────────────────────────────────────────────

    private void AddExeBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) TryAdd();
    }

    private void AddClick(object sender, RoutedEventArgs e) => TryAdd();

    private void TryAdd()
    {
        var raw = AddExeBox.Text.Trim();
        if (string.IsNullOrEmpty(raw)) return;

        // normalise: append .exe if user forgot it on Windows
        if (!raw.Contains('.'))
            raw += ".exe";
        raw = raw.ToLowerInvariant();

        // don't duplicate
        if (_items.Any(v => v.Id == $"custom:{raw}"))
        {
            AddExeBox.Text = string.Empty;
            AddExePlaceholder.Visibility = Visibility.Visible;
            return;
        }

        var id = $"custom:{raw}";
        var live = BuildLiveState(_getSnapshot().ToList(), _lastWake);   // synchronous (no wake probe)
        var vm = new HarnessVm(id, raw, "Custom", $"Custom monitored process: {raw}", isCustom: true, _settings,
            live);

        _items.Add(vm);
        HarnessList.ItemsSource = null;
        HarnessList.ItemsSource = _items;

        AddExeBox.Text = string.Empty;
        AddExePlaceholder.Visibility = Visibility.Visible;
    }

    private void DeleteClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: HarnessVm vm })
        {
            _items.Remove(vm);
            HarnessList.ItemsSource = null;
            HarnessList.ItemsSource = _items;
        }
    }

    // Open the per-harness settings dialog (Trust + modalities). Both apply live; refresh on save to update
    // the row's Trust badge.
    private void SettingsClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: HarnessVm vm }) OpenSettings(vm);
    }

    // Clicking the harness name opens the same settings dialog - a more discoverable affordance than the small gear link.
    private void HarnessNameClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement { DataContext: HarnessVm vm }) OpenSettings(vm);
    }

    private void OpenSettings(HarnessVm vm)
    {
        var w = new HarnessSettingsWindow(vm.Id, vm.DisplayName, _settings, GetCuDriver, SetCuDriver, GetCuAttentionTab)
        { Owner = Window.GetWindow(this) };
        if (w.ShowDialog() == true) Refresh();
    }

    // ── Placeholder visibility ────────────────────────────────────────────

    private void AddExeBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (AddExePlaceholder is not null)
            AddExePlaceholder.Visibility = string.IsNullOrEmpty(AddExeBox.Text)
                ? Visibility.Visible : Visibility.Collapsed;
    }

    // ── Save / Cancel ─────────────────────────────────────────────────────

    private void ConnectAgentClick(object sender, RoutedEventArgs e) => OpenConnectAgent?.Invoke();

    private async void SaveClick(object sender, RoutedEventArgs e) => await SaveChanges();

    /// <summary>Persists the current toggles + custom exes. Public so the host can save on navigate-away.</summary>
    public async Task<bool> SaveChanges()
    {
        using var provenance = SettingsChangeUiScope.Begin("save-harness-inventory");
        // Presence lock (P3): newly disabling a harness's monitoring is a weakening — gate before persist; deny reverts.
        var newlyDisabled = _items.Where(v => !v.IsMonitored).Select(v => v.Id)
            .Where(id => !_settings.DisabledHarnesses.Contains(id))
            .ToList();
        if (newlyDisabled.Count > 0 && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.DisableMonitoring, $"disable monitoring: {string.Join(", ", newlyDisabled)}"))
        {
            Revert();
            return false;   // denied — nothing persisted, toggles reverted
        }

        _settings.DisabledHarnesses = _items
            .Where(v => !v.IsMonitored)
            .Select(v => v.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        _settings.CustomHarnessExes = _items
            .Where(v => v.IsCustom)
            .Select(v => v.ExeName)
            .ToList();

        SettingsStore.Save(_settings);
        Refresh();   // reflect persisted state (this is a tab, so we stay put rather than closing)
        return true;
    }

    // Revert: rebuild rows from the persisted settings, discarding unsaved toggles.
    private void CancelClick(object sender, RoutedEventArgs e) => Revert();

    /// <summary>Discards unsaved edits by reloading from persisted settings.</summary>
    public void Revert() => Refresh();

    /// <summary>True if the current toggles / custom-exe list diverge from what's persisted.</summary>
    public bool HasUnsavedChanges()
    {
        var disabledNow = new HashSet<string>(
            _items.Where(v => !v.IsMonitored).Select(v => v.Id), StringComparer.OrdinalIgnoreCase);
        var customNow = new HashSet<string>(
            _items.Where(v => v.IsCustom).Select(v => v.ExeName), StringComparer.OrdinalIgnoreCase);

        return !disabledNow.SetEquals(_settings.DisabledHarnesses)
            || !customNow.SetEquals(new HashSet<string>(_settings.CustomHarnessExes, StringComparer.OrdinalIgnoreCase));
    }
}

/// <summary>View model for a single harness row.</summary>
public sealed class HarnessVm : INotifyPropertyChanged
{
    private bool _isMonitored;
    private bool _isRunning;
    private bool _wakeAvailable;
    private IReadOnlyList<WakeRequestEntry> _wakeRequests = [];
    private string? _wakeError;
    public event PropertyChangedEventHandler? PropertyChanged;

    public string  Id          { get; }
    public string  ExeName     { get; }   // raw exe name for custom entries
    public string  DisplayName { get; }
    public string  Developer   { get; }
    public string  Description { get; }
    public bool    IsCustom    { get; }
    public bool    IsRunning   { get => _isRunning; private set { _isRunning = value; Notify(nameof(IsRunning), nameof(StatusText), nameof(StatusBackground), nameof(StatusForeground)); } }
    public int     TrustLevel  { get; }

    public string  TrustButtonText => $"⚙ Trust {TrustLevel} · settings";
    public Visibility DeleteVisibility => IsCustom ? Visibility.Visible : Visibility.Collapsed;

    public bool IsMonitored
    {
        get => _isMonitored;
        set { _isMonitored = value; Notify(nameof(IsMonitored)); }
    }

    public string StatusText       => IsRunning ? "Running"  : "Not found";
    public Brush  StatusBackground => IsRunning
        ? new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x1A))
        : new SolidColorBrush(Color.FromRgb(0x1E, 0x20, 0x28));
    public Brush  StatusForeground => IsRunning
        ? new SolidColorBrush(Color.FromRgb(0x7E, 0xC8, 0x78))
        : new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90));

    public string WakeText => !_wakeAvailable ? "Wake n/a" : _wakeRequests.Count > 0 ? "Wake lock" : "No lock";
    public Brush WakeBackground => !_wakeAvailable
        ? new SolidColorBrush(Color.FromRgb(0x1E, 0x20, 0x28))
        : _wakeRequests.Count > 0
            ? new SolidColorBrush(Color.FromRgb(0x3B, 0x2A, 0x13))
            : new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x1A));
    public Brush WakeForeground => !_wakeAvailable
        ? new SolidColorBrush(Color.FromRgb(0x7A, 0x80, 0x90))
        : _wakeRequests.Count > 0
            ? new SolidColorBrush(Color.FromRgb(0xF0, 0xB4, 0x57))
            : new SolidColorBrush(Color.FromRgb(0x7E, 0xC8, 0x78));
    public string WakeToolTip => !_wakeAvailable
        ? $"Wake-lock detection needs the elevated sidecar. {_wakeError}".Trim()
        : _wakeRequests.Count == 0
            ? "No process wake requests attributed to this harness."
            : string.Join(Environment.NewLine, _wakeRequests.Select(r =>
                $"{r.Category}: {r.Image}{(string.IsNullOrWhiteSpace(r.Detail) ? string.Empty : " - " + r.Detail)}"));

    public HarnessVm(string id, string displayName, string developer, string description,
                     bool isCustom, ForemanSettings settings, HarnessLiveState live)
    {
        Id          = id;
        ExeName     = isCustom ? displayName : string.Empty;   // for custom, displayName IS the exe
        DisplayName = displayName;
        Developer   = developer;
        Description = description;
        IsCustom    = isCustom;
        _isRunning  = live.Running.Contains(id);
        TrustLevel  = settings.HarnessTrust.TryGetValue(id, out var t) ? Math.Clamp(t, 1, 5) : 3;
        _isMonitored = !settings.DisabledHarnesses.Contains(id);
        ApplyWake(live);
    }

    public void UpdateLive(HarnessLiveState live)
    {
        IsRunning = live.Running.Contains(Id);
        ApplyWake(live);
        Notify(nameof(WakeText), nameof(WakeBackground), nameof(WakeForeground), nameof(WakeToolTip));
    }

    private void ApplyWake(HarnessLiveState live)
    {
        _wakeAvailable = live.WakeAvailable;
        _wakeError = live.WakeError;
        _wakeRequests = live.WakeByHarness.TryGetValue(Id, out var requests) ? requests : [];
    }

    private void Notify(params string[] names)
    {
        foreach (var name in names)
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

public sealed record HarnessLiveState(
    HashSet<string> Running,
    bool WakeAvailable,
    IReadOnlyDictionary<string, List<WakeRequestEntry>> WakeByHarness,
    string? WakeError);

internal sealed record WakeByHarness(
    bool Available,
    Dictionary<string, List<WakeRequestEntry>> ByHarness,
    string? Error);
