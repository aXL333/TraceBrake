using Foreman.App.Security;
using Foreman.Core.Mcp;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

/// <summary>
/// Per-harness settings: the Trust 1-5 selector (drives escalation, auto-response, and universal capability
/// profiles via TrustPreset/UniversalTrustSettings) and the
/// self-service modality selection (the restricted sysprompt, delivered over MCP). Both apply LIVE — the
/// BehaviorTracker resolver reads settings.EffectiveThresholds and the MCP state shares the modalities dict,
/// so no restart is needed. Opened as a modal from a harness row.
/// </summary>
public partial class HarnessSettingsWindow : Window
{
    private sealed record TrustLevelOption(int Level, string Label);
    private sealed record CapabilityOption(HarnessCapabilityAccess Access, string Label);

    private static readonly TrustLevelOption[] TrustLevels =
    [
        new(1, "Trust 1 — Locked-down"),
        new(2, "Trust 2 — Strict"),
        new(3, "Trust 3 — Standard (default)"),
        new(4, "Trust 4 — Trusted"),
        new(5, "Trust 5 — Hands-off"),
    ];

    private static readonly CapabilityOption[] CapabilityOptions =
    [
        new(HarnessCapabilityAccess.Allow, "Use universal Trust profile"),
        new(HarnessCapabilityAccess.AskFirst, "Always ask"),
        new(HarnessCapabilityAccess.Block, "Never"),
    ];

    private readonly string _harnessId;
    private readonly ForemanSettings _settings;
    private readonly List<CheckBox> _modalityChecks = [];
    private readonly Func<string?>? _getCuDriver;
    private readonly Func<string?, Task<(bool Ok, string Reason)>>? _setCuDriver;
    private readonly Func<string?>? _getCuAttentionTab;

    public HarnessSettingsWindow(string harnessId, string displayName, ForemanSettings settings,
        Func<string?>? getCuDriver = null,
        Func<string?, Task<(bool Ok, string Reason)>>? setCuDriver = null,
        Func<string?>? getCuAttentionTab = null)
    {
        _harnessId = harnessId;
        _settings = settings;
        _getCuDriver = getCuDriver;
        _setCuDriver = setCuDriver;
        _getCuAttentionTab = getCuAttentionTab;
        InitializeComponent();
        TitleText.Text = $"{displayName} — TraceBrake settings";
        Populate();
    }

    private void Populate()
    {
        // Badges: Trust, placement (on-device vs cloud), one-click integration.
        AddBadge($"🛡 Trust {(int)CurrentTrust()}");
        AddBadge(Placement(_harnessId));
        AddBadge(HarnessIntegrationRegistry.Get(_harnessId) is not null ? "🔌 One-click" : "manual setup");

        TrustLevelCombo.ItemsSource = TrustLevels;
        TrustLevelCombo.DisplayMemberPath = nameof(TrustLevelOption.Label);
        TrustLevelCombo.SelectedItem = TrustLevels.First(x => x.Level == CurrentTrust());
        UpdateTrustSummary();

        foreach (var combo in new[] { ComputerUseCombo, BrowserUseCombo })
        {
            combo.ItemsSource = CapabilityOptions;
            combo.DisplayMemberPath = nameof(CapabilityOption.Label);
        }
        var capabilities = CurrentCapabilityRestrictions();
        ComputerUseCombo.SelectedItem = CapabilityOptions.First(x => x.Access == capabilities.ComputerUse);
        BrowserUseCombo.SelectedItem = CapabilityOptions.First(x => x.Access == capabilities.BrowserUse);

        var enabled = _settings.EnabledModalities(_harnessId);
        foreach (var m in ModalityCatalog.ForAudience(ModalityAudience.Agent))
        {
            var cb = new CheckBox
            {
                Content = $"{m.Title}  —  {m.Instruction}",
                IsChecked = enabled.Contains(m.Id, StringComparer.OrdinalIgnoreCase),
                Tag = m.Id,
                Margin = new Thickness(0, 4, 0, 4),
                Foreground = (System.Windows.Media.Brush)FindResource("TextPrimaryBrush"),
            };
            _modalityChecks.Add(cb);
            ModalityPanel.Children.Add(cb);
        }

        // TraceBrake's shared browser/Android DRIVER set (global, operator-only). Distinct from the Allow/Ask/Block
        // capabilities above: policy says what THIS harness may request; the driver set says which harnesses Foreman
        // currently accepts cu_* submissions from. Hidden when the host didn't wire the hook (e.g. headless).
        if (_setCuDriver is null)
        {
            CuDriverPanel.Visibility = Visibility.Collapsed;
        }
        else
        {
            ForemanDriverCombo.SelectedIndex = 0;   // safe default: saving policy/trust edits does not reroute CU.
            var driver = _getCuDriver?.Invoke();
            var included = IsCurrentDriver(driver);
            CuDriverNote.Text =
                $"Current TraceBrake driver set: {FormatDriverSet(driver)}. " +
                $"This harness is {(included ? "included" : "not included")}. Choose a mode only if you want to change TraceBrake's shared routing.";

            var tab = _getCuAttentionTab?.Invoke();
            CuAttentionNote.Text = string.IsNullOrWhiteSpace(tab)
                ? "No shared attention tab is pinned. When the browser extension pins one, TraceBrake keeps it separately from driver routing."
                : $"Shared attention tab: {tab}. Changing the driver set keeps this background tab state, so another harness can hand off and you can return to the same pinned tab.";
        }
    }

    /// <summary>True if the current driver string (null / "*" / comma-joined ids) authorizes THIS harness.</summary>
    private bool IsCurrentDriver(string? driver)
    {
        if (string.IsNullOrWhiteSpace(driver)) return false;
        if (driver.Trim() == "*") return true;   // "any harness" includes this one
        return driver.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     .Any(d => string.Equals(d, _harnessId, StringComparison.OrdinalIgnoreCase));
    }

    private static HashSet<string> ParseDriverSet(string? driver)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(driver)) return set;
        if (driver.Trim() == "*") { set.Add("any"); return set; }
        foreach (var d in driver.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            set.Add(string.Equals(d, "*", StringComparison.Ordinal) ? "any" : d.Trim().ToLowerInvariant());
        return set;
    }

    private static string? ComposeDriverSet(HashSet<string> set)
    {
        if (set.Contains("any")) return "any";
        var ids = set.Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim().ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return ids.Length == 0 ? null : string.Join(",", ids);
    }

    private static string FormatDriverSet(string? driver)
    {
        if (string.IsNullOrWhiteSpace(driver)) return "operator only";
        if (driver.Trim() == "*") return "any harness";
        return driver.Replace(",", ", ");
    }

    private string? EditedDriverSet(string? current)
    {
        var tag = (ForemanDriverCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "unchanged";
        var set = ParseDriverSet(current);
        switch (tag)
        {
            case "include":
                if (!set.Contains("any")) set.Add(_harnessId);
                return ComposeDriverSet(set);
            case "remove":
                set.Remove(_harnessId);
                return ComposeDriverSet(set);
            case "only":
                return _harnessId;
            case "any":
                return "any";
            case "operator":
                return null;
            default:
                return current;
        }
    }

    private bool DriverEditSelected() =>
        !string.Equals((ForemanDriverCombo.SelectedItem as ComboBoxItem)?.Tag as string, "unchanged",
            StringComparison.OrdinalIgnoreCase);

    private int CurrentTrust() =>
        _settings.HarnessTrust.TryGetValue(_harnessId, out var lvl) ? Math.Clamp(lvl, 1, 5) : 3;

    private int SelectedTrust() =>
        TrustLevelCombo.SelectedItem is TrustLevelOption option ? option.Level : CurrentTrust();

    private void TrustLevelCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        => UpdateTrustSummary();

    private void UpdateTrustSummary()
    {
        if (TrustSummary is null) return;
        var level = SelectedTrust();
        var behaviour = level switch
        {
            1 => "Locked-down — fires on the first hint; asks + audits aggressively; strict enforce.",
            2 => "Strict — less rope, more nope: fires early; audits on high severity.",
            3 => "Standard (default) — today's balanced thresholds.",
            4 => "Trusted — more rope before escalating; fewer prompts.",
            5 => "Hands-off — only sustained or catastrophic behaviour escalates (Emergency rules + Critical reads still fire).",
            _ => "",
        };
        var profile = (_settings.UniversalTrust ?? new UniversalTrustSettings()).ForLevel(level);
        TrustSummary.Text = behaviour + Environment.NewLine
            + $"Universal profile — browser observe/control: {Short(profile.BrowserObservation)} / {Short(profile.BrowserControl)}; "
            + $"desktop: {Short(profile.DesktopObservation)} / {Short(profile.DesktopControl)}; "
            + $"ADB: {Short(profile.AdbObservation)} / {Short(profile.AdbControl)}.";
    }

    private static string Short(TrustPrivilegeMode mode) => mode switch
    {
        TrustPrivilegeMode.Never => "never",
        TrustPrivilegeMode.AskEveryTime => "ask",
        TrustPrivilegeMode.UnattendedWhileUnlocked => "unattended unlocked",
        TrustPrivilegeMode.UnattendedIncludingLocked => "unattended incl. locked",
        _ => "blocked",
    };

    private void UniversalTrustSettingsClick(object sender, RoutedEventArgs e)
    {
        var window = new UniversalTrustSettingsWindow(_settings)
        {
            Owner = this,
        };
        if (window.ShowDialog() == true)
            UpdateTrustSummary();
    }

    private void AddBadge(string text)
    {
        BadgePanel.Children.Add(new Border
        {
            Style = (Style)FindResource("Badge"),
            Child = new TextBlock
            {
                Text = text,
                FontSize = 11,
                Foreground = (System.Windows.Media.Brush)FindResource("TextPrimaryBrush"),
                FontFamily = new System.Windows.Media.FontFamily("Segoe UI, Arial"),
            },
        });
    }

    private static string Placement(string harnessId)
    {
        if (harnessId.Equals("lm-studio", StringComparison.OrdinalIgnoreCase)) return "🏠 On-device";
        if (harnessId.StartsWith("custom:", StringComparison.OrdinalIgnoreCase)) return "❓ Custom";
        return "☁ Cloud model";
    }

    private HarnessCapabilityRestrictions CurrentCapabilityRestrictions() =>
        _settings.EffectiveCapabilityRestrictions(_harnessId);

    private static HarnessCapabilityAccess SelectedAccess(ComboBox combo) =>
        combo.SelectedItem is CapabilityOption option ? option.Access : HarnessCapabilityAccess.Allow;

    private static bool IsDefault(HarnessCapabilityRestrictions restrictions) =>
        restrictions.ComputerUse == HarnessCapabilityAccess.Allow
        && restrictions.BrowserUse == HarnessCapabilityAccess.Allow;

    private static bool SameCapabilities(HarnessCapabilityRestrictions a, HarnessCapabilityRestrictions b) =>
        a.ComputerUse == b.ComputerUse && a.BrowserUse == b.BrowserUse;

    private static bool RelaxesCapabilities(HarnessCapabilityRestrictions oldRestrictions, HarnessCapabilityRestrictions newRestrictions) =>
        newRestrictions.ComputerUse < oldRestrictions.ComputerUse
        || newRestrictions.BrowserUse < oldRestrictions.BrowserUse;

    private async void SaveClick(object sender, RoutedEventArgs e)
    {
        using var provenance = SettingsChangeUiScope.Begin("save-harness-settings");
        // Presence lock (P3): raising the numerical Trust level loosens behaviour thresholds and may select a more
        // permissive capability profile. Moving toward Trust 1 is the stricter direction.
        var oldTrust = (int)CurrentTrust();
        var newTrust = SelectedTrust();
        var newModalities = _modalityChecks.Where(cb => cb.IsChecked == true).Select(cb => (string)cb.Tag).ToList();
        var oldModalities = _settings.HarnessModalities.TryGetValue(_harnessId, out var m) ? m : [];
        var modalitiesChanged = !new HashSet<string>(oldModalities, StringComparer.OrdinalIgnoreCase).SetEquals(newModalities);
        var oldCapabilities = CurrentCapabilityRestrictions();
        var newCapabilities = new HarnessCapabilityRestrictions
        {
            ComputerUse = SelectedAccess(ComputerUseCombo),
            BrowserUse = SelectedAccess(BrowserUseCombo),
        };
        var capabilitiesChanged = !SameCapabilities(oldCapabilities, newCapabilities);

        if (newTrust > oldTrust && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.LowerTrust, $"{_harnessId}: Trust {oldTrust}→{newTrust}"))
            return;
        if (modalitiesChanged && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.EditHarnessSysprompt, $"{_harnessId}: modalities edited"))
            return;
        if (capabilitiesChanged
            && RelaxesCapabilities(oldCapabilities, newCapabilities)
            && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.RelaxHarnessCapabilityRestriction,
                $"{_harnessId}: high-risk tool restrictions relaxed"))
            return;

        // TraceBrake's shared browser/Android driver set (global, operator-only, persisted via the CuBroker's own persister)
        // is separate from the per-harness policy dicts below. Edits preserve the existing set unless the operator
        // explicitly chooses "only", "any", or "operator only"; changing it does not clear the shared attention tab.
        if (_setCuDriver is not null && DriverEditSelected())
        {
            var driverResult = await _setCuDriver(EditedDriverSet(_getCuDriver?.Invoke()));
            if (!driverResult.Ok)
            {
                StatusText.Text = "Driver unchanged: " + driverResult.Reason;
                return;
            }
        }

        _settings.HarnessTrust[_harnessId] = newTrust;
        _settings.HarnessModalities[_harnessId] = newModalities;
        if (IsDefault(newCapabilities))
            _settings.HarnessCapabilityRestrictions.Remove(_harnessId);
        else
            _settings.HarnessCapabilityRestrictions[_harnessId] = newCapabilities;
        try
        {
            SettingsStore.Save(_settings);
            DialogResult = true;
            Close();
        }
        catch (System.Exception ex)
        {
            StatusText.Text = "Couldn't save: " + ex.Message;
        }
    }

    private void CancelClick(object sender, RoutedEventArgs e) => Close();
}
