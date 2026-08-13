using Foreman.App.Security;
using Foreman.Core.Models;
using Foreman.Core.Settings;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

/// <summary>
/// Lists the operator's active alert mutes and lets them be removed. Mutes only quiet tray popups (never stop
/// detection). Hosted as the Dashboard "Mutes" tab (was a standalone window). Refreshed on tab-show so it reflects
/// mutes added/expired elsewhere.
/// </summary>
public partial class MutesView : UserControl
{
    private readonly ForemanSettings _settings;
    private readonly Action _persist;

    public MutesView(ForemanSettings settings, Action persist)
    {
        _settings = settings;
        _persist = persist;
        InitializeComponent();
        Loaded += (_, _) => RefreshState();
    }

    /// <summary>Re-read the mute list. Called on load and on tab-show.</summary>
    public void RefreshState()
    {
        var now = DateTimeOffset.UtcNow;
        var rows = _settings.Mutes
            .OrderBy(m => m.Until ?? DateTimeOffset.MaxValue)
            .Select(m => new MuteRowVm(m, now))
            .ToList();

        MuteList.ItemsSource = rows;
        EmptyLabel.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ClearExpiredButton.IsEnabled = _settings.Mutes.Any(m => m.Until is { } u && u <= now);
        ClearAllButton.IsEnabled = _settings.Mutes.Count > 0;
    }

    private void RemoveClick(object sender, RoutedEventArgs e)
    {
        using var provenance = SettingsChangeUiScope.Begin("remove-alert-mute");
        if (sender is FrameworkElement { Tag: MuteEntry entry })
        {
            _settings.Mutes.Remove(entry);
            _persist();
            RefreshState();
        }
    }

    private void ClearExpiredClick(object sender, RoutedEventArgs e)
    {
        using var provenance = SettingsChangeUiScope.Begin("clear-expired-alert-mutes");
        var now = DateTimeOffset.UtcNow;
        _settings.Mutes.RemoveAll(m => m.Until is { } u && u <= now);
        _persist();
        RefreshState();
    }

    private void ClearAllClick(object sender, RoutedEventArgs e)
    {
        using var provenance = SettingsChangeUiScope.Begin("clear-all-alert-mutes");
        _settings.Mutes.Clear();
        _persist();
        RefreshState();
    }
}

/// <summary>Row VM for the mute list.</summary>
public sealed class MuteRowVm
{
    public MuteEntry Entry { get; }
    public string What { get; }
    public string Status { get; }

    public MuteRowVm(MuteEntry entry, DateTimeOffset now)
    {
        Entry = entry;
        What = string.IsNullOrWhiteSpace(entry.Label) ? $"{entry.Scope}: {entry.Value}" : entry.Label;
        Status = entry.Until switch
        {
            null                => "Muted until cleared",
            { } u when u <= now => "Expired (will clear on its own)",
            { } u               => $"Muted until {u.ToLocalTime():g}",
        };
    }
}
