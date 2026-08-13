using Foreman.App.Security;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

/// <summary>Edits the shared Trust 1–5 browser, desktop and Android capability profiles.</summary>
public partial class UniversalTrustSettingsWindow : Window
{
    private sealed record TrustLevelOption(int Level, string Label);
    private sealed record ModeOption(TrustPrivilegeMode Mode, string Label);

    private static readonly TrustLevelOption[] TrustLevels =
    [
        new(1, "Trust 1 — Locked-down"),
        new(2, "Trust 2 — Strict"),
        new(3, "Trust 3 — Standard (default)"),
        new(4, "Trust 4 — Trusted"),
        new(5, "Trust 5 — Hands-off"),
    ];

    private static readonly ModeOption[] Modes =
    [
        new(TrustPrivilegeMode.Never, "Never"),
        new(TrustPrivilegeMode.AskEveryTime, "Ask every time"),
        new(TrustPrivilegeMode.UnattendedWhileUnlocked, "Unattended while unlocked"),
        new(TrustPrivilegeMode.UnattendedIncludingLocked, "Unattended, including while locked"),
    ];

    private readonly ForemanSettings _settings;
    private readonly UniversalTrustSettings _original;
    private UniversalTrustSettings _working;
    private int _loadedLevel = 3;
    private bool _loading;

    private IEnumerable<ComboBox> ModeCombos =>
    [
        BrowserObservationCombo,
        DesktopObservationCombo,
        AdbObservationCombo,
        BrowserControlCombo,
        DesktopControlCombo,
        AdbControlCombo,
    ];

    public UniversalTrustSettingsWindow(ForemanSettings settings)
    {
        _settings = settings;
        _original = (settings.UniversalTrust ?? new UniversalTrustSettings()).Clone();
        _working = _original.Clone();
        InitializeComponent();

        _loading = true;
        TrustLevelCombo.ItemsSource = TrustLevels;
        TrustLevelCombo.DisplayMemberPath = nameof(TrustLevelOption.Label);

        foreach (var combo in ModeCombos)
        {
            combo.ItemsSource = Modes;
            combo.DisplayMemberPath = nameof(ModeOption.Label);
        }

        TrustLevelCombo.SelectedItem = TrustLevels.First(x => x.Level == _loadedLevel);
        _loading = false;
        LoadProfile(_loadedLevel);
    }

    private void TrustLevelSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || !IsInitialized) return;
        StoreProfile(_loadedLevel);
        _loadedLevel = SelectedLevel();
        LoadProfile(_loadedLevel);
    }

    private int SelectedLevel() =>
        TrustLevelCombo.SelectedItem is TrustLevelOption option ? option.Level : _loadedLevel;

    private void LoadProfile(int level)
    {
        _loading = true;
        try
        {
            var profile = _working.ForLevel(level);
            BrowserObservationCombo.SelectedItem = ModeOptionFor(profile.BrowserObservation);
            BrowserControlCombo.SelectedItem = ModeOptionFor(profile.BrowserControl);
            DesktopObservationCombo.SelectedItem = ModeOptionFor(profile.DesktopObservation);
            DesktopControlCombo.SelectedItem = ModeOptionFor(profile.DesktopControl);
            AdbObservationCombo.SelectedItem = ModeOptionFor(profile.AdbObservation);
            AdbControlCombo.SelectedItem = ModeOptionFor(profile.AdbControl);
        }
        finally { _loading = false; }
    }

    private void StoreProfile(int level)
    {
        _working.Profiles[Math.Clamp(level, 1, 5)] = new TrustCapabilityProfile
        {
            BrowserObservation = SelectedMode(BrowserObservationCombo),
            BrowserControl = SelectedMode(BrowserControlCombo),
            DesktopObservation = SelectedMode(DesktopObservationCombo),
            DesktopControl = SelectedMode(DesktopControlCombo),
            AdbObservation = SelectedMode(AdbObservationCombo),
            AdbControl = SelectedMode(AdbControlCombo),
        };
    }

    private static TrustPrivilegeMode SelectedMode(ComboBox combo) =>
        combo.SelectedItem is ModeOption option ? option.Mode : TrustPrivilegeMode.Never;

    private static ModeOption ModeOptionFor(TrustPrivilegeMode mode) =>
        Modes.FirstOrDefault(x => x.Mode == mode) ?? Modes[0];

    private void ResetCurrentClick(object sender, RoutedEventArgs e)
    {
        _working.Profiles[SelectedLevel()] = UniversalTrustSettings.CreateDefaultProfile();
        LoadProfile(SelectedLevel());
        StatusText.Text = $"Trust {SelectedLevel()} reset to the compatibility defaults. Save to apply.";
    }

    private void ResetAllClick(object sender, RoutedEventArgs e)
    {
        _working = new UniversalTrustSettings();
        LoadProfile(SelectedLevel());
        StatusText.Text = "All five profiles reset to the compatibility defaults. Save to apply.";
    }

    private async void SaveClick(object sender, RoutedEventArgs e)
    {
        using var provenance = SettingsChangeUiScope.Begin("save-universal-trust-settings");
        StoreProfile(SelectedLevel());
        var relaxation = Enumerable.Range(1, 5).Any(level =>
            TrustCapabilityPolicy.IsRelaxation(_original.ForLevel(level), _working.ForLevel(level)));

        if (relaxation && !await PresenceGuard.AuthorizeAsync(
                WeakeningAction.RelaxHarnessCapabilityRestriction,
                "Universal Trust browser/desktop/ADB capability profiles relaxed"))
        {
            StatusText.Text = "Presence was not verified; the weaker permissions were not saved.";
            return;
        }

        try
        {
            var previous = _settings.UniversalTrust;
            _settings.UniversalTrust = _working.Clone();
            try
            {
                SettingsStore.Save(_settings);
                DialogResult = true;
                Close();
            }
            catch
            {
                // The broker reads the live settings object. A disk-write failure must not leave an unsaved policy
                // active for the rest of the session.
                _settings.UniversalTrust = previous;
                throw;
            }
        }
        catch (Exception ex)
        {
            StatusText.Text = "Couldn't save: " + ex.Message;
        }
    }

    private void CancelClick(object sender, RoutedEventArgs e) => Close();
}
