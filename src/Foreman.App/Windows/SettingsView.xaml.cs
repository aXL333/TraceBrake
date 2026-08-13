using Foreman.Core.Alerts;
using Foreman.Core.Security;
using Foreman.Core.Settings;
using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

/// <summary>Settings surface, hosted as the Dashboard "Settings" tab (was a standalone window). Changes apply on
/// Save (some, like port + guardian, need a restart); Revert discards unsaved edits in place.</summary>
public partial class SettingsView : UserControl
{
    private readonly ForemanSettings _settings;
    private readonly Action<bool>? _onRunElevatedChanged;
    private readonly Action<bool>? _onScanMcpToolsChanged;
    private readonly Action? _onDecoyAuditChanged;
    private readonly Action? _onAdbBridgeChanged;

    public SettingsView(ForemanSettings settings,
                        Action<bool>? onRunElevatedChanged = null,
                        Action<bool>? onScanMcpToolsChanged = null,
                        Action? onDecoyAuditChanged = null,
                        Action? onAdbBridgeChanged = null)
    {
        _settings = settings;
        _onRunElevatedChanged = onRunElevatedChanged;
        _onScanMcpToolsChanged = onScanMcpToolsChanged;
        _onDecoyAuditChanged = onDecoyAuditChanged;
        _onAdbBridgeChanged = onAdbBridgeChanged;
        InitializeComponent();
        Populate();
        RefreshPresenceLock();
        RefreshGuardian();
    }

    private void RefreshGuardian()
    {
        var on = GuardianControl.IsInstalled;
        var mode = on ? GuardianTrust.ProbeInstalledMode() : string.Empty;
        GuardianButton.Content = on ? "Disable hardened guardian..." : "Enable hardened guardian...";
        GuardianStatus.Text = mode switch
        {
            GuardianTrust.PublisherSigned => "Active (LocalSystem, publisher authenticated).",
            GuardianTrust.PathHashPinned => "Active (LocalSystem, unsigned development path + hash pin).",
            "legacy_or_unavailable" => "Installed, but unavailable or legacy; TraceBrake is ignoring it.",
            _ => "Off (per-user, tamper-evident).",
        };
    }

    // Install / remove the opt-in guardian service. Immediate action (one UAC), independent of the Save button —
    // mirrors the presence-lock pattern. Activation of hardened sealing takes effect on the next TraceBrake restart.
    private void HardenedGuardianClick(object sender, RoutedEventArgs e)
    {
        if (GuardianControl.IsInstalled)
        {
            if (MessageBox.Show(
                    "Disable the hardened guardian? This removes the LocalSystem service and returns the tamper-seal " +
                    "to the per-user (tamper-evident, not tamper-proof) mode. One UAC prompt.",
                    "TraceBrake — Hardened guardian", MessageBoxButton.YesNo, MessageBoxImage.Warning)
                != MessageBoxResult.Yes)
                return;

            var (ok, msg) = GuardianControl.Uninstall();
            MessageBox.Show(msg, "TraceBrake — Hardened guardian", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshGuardian();
            return;
        }

        var signed = SidecarIntegrity.SelfIsSigned();
        var posture = signed
            ? "This signed build will authenticate future TraceBrake versions from the same verified publisher."
            : "This unsigned build will use a development-only TraceBrake.exe path + SHA-256 pin. It prevents arbitrary " +
              "local callers, but is NOT publisher-authenticated or a commercial tamper-proof boundary. Re-enable the " +
              "guardian after a certificate is added to upgrade automatically to publisher trust.";
        if (MessageBox.Show(
                "Install the hardened guardian?\n\n" +
                "Registers a small LocalSystem Windows service that holds TraceBrake's tamper-seal key outside the normal " +
                $"user process. {posture}\n\nOne UAC prompt; you can disable it here later.",
                "TraceBrake — Enable hardened guardian", MessageBoxButton.OKCancel, MessageBoxImage.Question)
            != MessageBoxResult.OK)
            return;

        var (ok2, msg2) = GuardianControl.Install();
        MessageBox.Show(
            msg2 + (ok2 ? "\n\nRestart TraceBrake to activate hardened sealing." : ""),
            "TraceBrake — Hardened guardian", MessageBoxButton.OK,
            ok2 ? MessageBoxImage.Information : MessageBoxImage.Warning);
        RefreshGuardian();
    }

    private void RefreshPresenceLock()
    {
        var on = Security.PresenceGuard.IsEnabled;
        PresenceLockButton.Content = on ? "Disable presence lock..." : "Enable presence lock...";
        PresenceLockStatus.Text = on
            ? $"Armed ({Security.PresenceGuard.AuthenticatorLabel ?? "authenticator"})."
            : Security.PresenceGuard.IsAvailable ? "Off." : "Off — no authenticator available.";
        PinEveryTapCheck.IsChecked = _settings.PresenceLock.RequireUserVerification;
        PinEveryTapCheck.IsEnabled = Security.PresenceGuard.IsAvailable;
    }

    // Touch-only (default, unchecked) vs full PIN/biometric on roaming keys. Persisted immediately — like the
    // enroll button, independent of the Save button — and read live by the verifier, so it takes effect on the
    // next tap. Not a sealed field (a silent flip can't help a rogue agent that still can't touch the key), so
    // saving leaves the settings seal unchanged.
    private void PinEveryTapClick(object sender, RoutedEventArgs e)
    {
        using var provenance = Security.SettingsChangeUiScope.Begin("change-presence-verification-mode");
        _settings.PresenceLock.RequireUserVerification = PinEveryTapCheck.IsChecked == true;
        try { SettingsStore.Save(_settings); }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not save the setting: {ex.Message}", "TraceBrake — Presence lock",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // Enroll / disarm the presence lock from the (visible, on-screen) Settings dialog — the reliable WebAuthn
    // owner window. Acts immediately + persists; independent of the Save button below.
    private async void PresenceLockClick(object sender, RoutedEventArgs e)
    {
        using var provenance = Security.SettingsChangeUiScope.Begin("change-presence-lock");
        if (Security.PresenceGuard.IsEnabled)
        {
            var (ok, msg) = await Security.PresenceGuard.DisableAsync();
            MessageBox.Show(msg, "TraceBrake — Presence lock", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshPresenceLock();
            return;
        }

        if (!Security.PresenceGuard.IsAvailable)
        {
            MessageBox.Show(
                "No authenticator available. Set up Windows Hello (a PIN or biometric in Windows Settings → " +
                "Accounts → Sign-in options) or attach a FIDO2 security key, then try again.",
                "TraceBrake — Presence lock", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var choice = MessageBox.Show(
            "Require a Windows Hello or security-key tap to WEAKEN TraceBrake?\n\n" +
            "YES = Strict (also requires a tap to QUIT TraceBrake — most secure, but can be annoying)\n" +
            "NO = Standard (recommended)\n" +
            "Cancel = don't enable",
            "TraceBrake — Enable presence lock", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        if (choice == MessageBoxResult.Cancel) return;

        var scope = choice == MessageBoxResult.Yes
            ? Foreman.Core.Security.LockScope.Strict
            : Foreman.Core.Security.LockScope.Standard;
        var (ok2, msg2) = await Security.PresenceGuard.EnableAsync(scope);
        MessageBox.Show(msg2, "TraceBrake — Presence lock", MessageBoxButton.OK,
            ok2 ? MessageBoxImage.Information : MessageBoxImage.Warning);
        RefreshPresenceLock();
    }

    private void Populate()
    {
        // General — the HKCU Run entry is the source of truth, not a settings field,
        // so the checkbox always reflects what Windows will actually do at sign-in.
        StartWithWindowsCheck.IsChecked = StartupManager.IsEnabled();
        GameModeCheck.IsChecked             = _settings.GameMode.Enabled;
        GameModeBreakThroughCheck.IsChecked = _settings.GameMode.AllowCriticalBreakThrough;

        // MCP
        McpPortBox.Text    = _settings.McpPort.ToString();

        // Process thresholds
        HangBox.Text       = _settings.HangThresholdMinutes.ToString();
        SuppressBox.Text   = (_settings.CadenceGovernor.RepeatSuppressSeconds / 60).ToString();
        HangRealertBox.Text = _settings.HangRealertCooldownMinutes.ToString();

        // Notifications
        NotifyHangCheck.IsChecked    = _settings.NotifyOnHang;
        NotifyOrphanCheck.IsChecked  = _settings.NotifyOnOrphan;
        NotifyCriticalCheck.IsChecked = _settings.NotifyOnCriticalCommand;
        CoalesceNotifyCheck.IsChecked = _settings.CadenceGovernor.Enabled;
        ScaleIdleCheck.IsChecked      = _settings.IdleThresholdScaling.Enabled;
        OsEventLogCheck.IsChecked     = _settings.OsEventLog.Enabled;
        PersistLogCheck.IsChecked    = _settings.EventLogPersist;
        MonitorAllCheck.IsChecked    = _settings.MonitorAllProcesses;
        RunElevatedCheck.IsChecked   = _settings.RunElevated;
        ScanMcpToolsCheck.IsChecked  = _settings.ScanMcpTools;
        AdbEnabledCheck.IsChecked    = _settings.AdbBridge.Enabled;
        AdbPathBox.Text              = _settings.AdbBridge.ExecutablePath ?? DiscoverAdbPath() ?? string.Empty;
        AdbDevicesBox.Text           = string.Join(", ", _settings.AdbBridge.EnrolledDeviceSerials);
        IdleCleanupCheck.IsChecked   = _settings.IdleCleanupEnabled;
        IdleCleanupAfterBox.Text     = _settings.IdleCleanupAfterMinutes.ToString();

        // Decoy credentials
        var dc = _settings.DecoyCredentials;
        DecoyCredsCheck.IsChecked     = dc.Enabled;
        DecoyReadAuditCheck.IsChecked = dc.EnableReadAuditing;
        DecoyAwsCanaryCheck.IsChecked = dc.IncludeAwsCanaryToken;
        DecoyAwsKeyIdBox.Text         = dc.AwsCanaryAccessKeyId ?? string.Empty;
        DecoyAwsSecretBox.Text        = dc.AwsCanarySecretAccessKey ?? string.Empty;
        DecoyStatusText.Text          = dc.PlantedPaths.Count > 0
            ? $"Currently planted: {dc.PlantedPaths.Count} decoy file(s)."
            : "No decoys planted yet.";

        // Escalation thresholds
        AlertMediumBox.Text    = _settings.AlertLevelMediumCount.ToString();
        AlarmHighBox.Text      = _settings.AlarmLevelHighCount.ToString();
        AlarmRulesBox.Text     = _settings.AlarmLevelUniqueRules.ToString();
        AlarmCatsBox.Text      = _settings.AlarmLevelCategories.ToString();
        EmergencyTotalBox.Text = _settings.EmergencyLevelTotalAlerts.ToString();
        EmergencyRulesBox.Text = string.Join(", ", _settings.EmergencyRuleIds);

        // Automatic responses per tier (Alert audit stays disabled — not audit-worthy on its own).
        var ar = _settings.AlertResponses;
        AlertAskCheck.IsChecked        = ar.OnAlert.HasFlag(EscalationAction.AskHarness);
        AlertCleanupCheck.IsChecked    = ar.OnAlert.HasFlag(EscalationAction.RequestSelfCleanup);
        AlarmAskCheck.IsChecked        = ar.OnAlarm.HasFlag(EscalationAction.AskHarness);
        AlarmAuditCheck.IsChecked      = ar.OnAlarm.HasFlag(EscalationAction.AdversarialAudit);
        AlarmCleanupCheck.IsChecked    = ar.OnAlarm.HasFlag(EscalationAction.RequestSelfCleanup);
        EmergencyAskCheck.IsChecked     = ar.OnEmergency.HasFlag(EscalationAction.AskHarness);
        EmergencyAuditCheck.IsChecked   = ar.OnEmergency.HasFlag(EscalationAction.AdversarialAudit);
        EmergencyCleanupCheck.IsChecked = ar.OnEmergency.HasFlag(EscalationAction.RequestSelfCleanup);
        AutoResponseCooldownBox.Text   = ar.CooldownMinutes.ToString();
        var scheduled = _settings.ScheduledAudit;
        ScheduledAuditCheck.IsChecked = scheduled.Enabled;
        ScheduledAuditEveryBox.Text = scheduled.EveryNEvents.ToString();
        ScheduledAuditIntervalBox.Text = scheduled.IntervalMinutes.ToString();
        ScheduledAuditCooldownBox.Text = scheduled.CooldownMinutes.ToString();
    }

    private static EscalationAction Compose(CheckBox? ask, CheckBox? audit, CheckBox? cleanup)
    {
        var a = EscalationAction.None;
        if (ask?.IsChecked == true)     a |= EscalationAction.AskHarness;
        if (audit?.IsChecked == true)   a |= EscalationAction.AdversarialAudit;
        if (cleanup?.IsChecked == true) a |= EscalationAction.RequestSelfCleanup;
        return AlertResponsePolicy.Sanitize(a);   // clamp to the allowed non-destructive set
    }

    private async void SaveClick(object sender, RoutedEventArgs e)
    {
        using var provenance = Security.SettingsChangeUiScope.Begin("save-main-settings");
        // ── MCP ─────────────────────────────────────────────────────────────
        if (!int.TryParse(McpPortBox.Text, out var port) || port is < 1024 or > 65535)
        { MessageBox.Show("Port must be 1024–65535.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        // ── Process thresholds ───────────────────────────────────────────────
        if (!int.TryParse(HangBox.Text, out var hang) || hang < 1)
        { MessageBox.Show("Hang threshold must be ≥ 1 minute.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(HangRealertBox.Text, out var hangRealert) || hangRealert < 0)
        { MessageBox.Show("Hang re-alert cooldown must be ≥ 0 minutes.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(SuppressBox.Text, out var suppressMin) || suppressMin < 0)
        { MessageBox.Show("Coalesce-repeats window must be ≥ 0 minutes.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(IdleCleanupAfterBox.Text, out var idleAfter) || idleAfter < 5)
        { MessageBox.Show("Idle cleanup threshold must be ≥ 5 minutes.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        // ── Escalation thresholds ────────────────────────────────────────────
        if (!int.TryParse(AlertMediumBox.Text, out var alertMed) || alertMed < 1)
        { MessageBox.Show("Alert medium threshold must be ≥ 1.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmHighBox.Text, out var alarmHigh) || alarmHigh < 1)
        { MessageBox.Show("Alarm high threshold must be ≥ 1.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmRulesBox.Text, out var alarmRules) || alarmRules < 1)
        { MessageBox.Show("Alarm rules threshold must be ≥ 1.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AlarmCatsBox.Text, out var alarmCats) || alarmCats < 1)
        { MessageBox.Show("Alarm category threshold must be ≥ 1.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(EmergencyTotalBox.Text, out var emergencyTotal) || emergencyTotal < 1)
        { MessageBox.Show("Emergency total threshold must be ≥ 1.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(AutoResponseCooldownBox.Text, out var arCooldown) || arCooldown < 0)
        { MessageBox.Show("Auto-response re-fire cooldown must be ≥ 0 minutes.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        if (!int.TryParse(ScheduledAuditEveryBox.Text, out var auditEvery) || auditEvery < 0)
        { MessageBox.Show("Scheduled-audit alert count must be ≥ 0.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        if (!int.TryParse(ScheduledAuditIntervalBox.Text, out var auditInterval) || auditInterval < 0)
        { MessageBox.Show("Scheduled-audit interval must be ≥ 0 minutes.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        if (!int.TryParse(ScheduledAuditCooldownBox.Text, out var auditCooldown) || auditCooldown < 0)
        { MessageBox.Show("Scheduled-audit cooldown must be ≥ 0 minutes.", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        if (ScheduledAuditCheck.IsChecked == true && auditEvery == 0 && auditInterval == 0)
        { MessageBox.Show("Enable at least one scheduled-audit trigger (alert count or interval).", "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning); return; }

        var adbEnabled = AdbEnabledCheck.IsChecked == true;
        var adbPath = AdbPathBox.Text.Trim();
        var adbDevices = AdbDevicesBox.Text
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (adbEnabled && (!Path.IsPathFullyQualified(adbPath) || !File.Exists(adbPath)))
        {
            MessageBox.Show("Choose an existing adb executable using its absolute path.",
                "TraceBrake — Android bridge", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        string? adbHash = null;
        if (Path.IsPathFullyQualified(adbPath) && File.Exists(adbPath))
        {
            try { adbHash = Foreman.Core.ComputerUse.AdbProcessRunner.ComputeSha256(adbPath); }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not hash-pin adb.exe: {ex.Message}",
                    "TraceBrake — Android bridge", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }
        var invalidSerial = adbDevices.FirstOrDefault(s => !Foreman.Core.ComputerUse.AdbBridgeExecutor.IsSafeSerial(s));
        if (invalidSerial is not null)
        {
            MessageBox.Show($"'{invalidSerial}' is not a valid ADB device serial.",
                "TraceBrake — Android bridge", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var emergencyRules = EmergencyRulesBox.Text
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(r => r.ToLowerInvariant())
            .Distinct()
            .ToArray();

        // ── Presence lock (P3): weakening toggles require an authorized tap. Checked BEFORE any mutation so a
        //    denied tap aborts the whole save with the old posture intact, and the reverted control shows why. ──
        var dc0 = _settings.DecoyCredentials;
        var wasAuditing = dc0.Enabled && dc0.EnableReadAuditing;
        var nowAuditing = DecoyCredsCheck.IsChecked == true && DecoyReadAuditCheck.IsChecked == true;
        if (wasAuditing && !nowAuditing && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.DisableReadAuditing, "credential read-auditing → off"))
        {
            DecoyCredsCheck.IsChecked = true; DecoyReadAuditCheck.IsChecked = true;   // revert; keep the dialog open
            return;
        }
        if (_settings.EventLogPersist && PersistLogCheck.IsChecked != true && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.DisableLogPersist, "persistent log → off (canary)"))
        {
            PersistLogCheck.IsChecked = true;
            return;
        }

        var oldAdb = _settings.AdbBridge;
        var addedAdbDevice = adbDevices.Except(oldAdb.EnrolledDeviceSerials, StringComparer.OrdinalIgnoreCase).Any();
        var adbAuthorityExpanded = (!oldAdb.Enabled && adbEnabled)
            || (adbEnabled && !string.Equals(oldAdb.ExecutablePath ?? string.Empty, adbPath, StringComparison.OrdinalIgnoreCase))
            || (adbEnabled && !string.Equals(oldAdb.ExecutableSha256 ?? string.Empty, adbHash ?? string.Empty, StringComparison.OrdinalIgnoreCase))
            || addedAdbDevice;
        if (adbAuthorityExpanded && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.EnrollAdbBridge,
                $"ADB bridge {(adbEnabled ? "enabled" : "configured")}; executable '{adbPath}'; devices [{string.Join(", ", adbDevices)}]",
                forcePresence: true, freshTap: true))
        {
            MessageBox.Show(
                "The Android bridge was not changed. Enrol and enable TraceBrake's presence lock, then approve the fresh verification prompt.",
                "TraceBrake — Android bridge", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // ── Commit ───────────────────────────────────────────────────────────
        var portChanged         = port != _settings.McpPort;
        var runElevatedChanged  = (RunElevatedCheck.IsChecked == true) != _settings.RunElevated;
        var scanMcpToolsChanged = (ScanMcpToolsCheck.IsChecked == true) != _settings.ScanMcpTools;
        var adbChanged = adbEnabled != oldAdb.Enabled
            || !string.Equals(oldAdb.ExecutablePath ?? string.Empty, adbPath, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(oldAdb.ExecutableSha256 ?? string.Empty, adbHash ?? string.Empty, StringComparison.OrdinalIgnoreCase)
            || !new HashSet<string>(oldAdb.EnrolledDeviceSerials, StringComparer.OrdinalIgnoreCase).SetEquals(adbDevices);

        _settings.McpPort                    = port;
        _settings.RunElevated                = RunElevatedCheck.IsChecked == true;
        _settings.ScanMcpTools               = ScanMcpToolsCheck.IsChecked == true;
        _settings.HangThresholdMinutes       = hang;
        _settings.CadenceGovernor.RepeatSuppressSeconds = suppressMin * 60;
        _settings.HangRealertCooldownMinutes = hangRealert;
        _settings.NotifyOnHang               = NotifyHangCheck.IsChecked == true;
        _settings.NotifyOnOrphan             = NotifyOrphanCheck.IsChecked == true;
        _settings.NotifyOnCriticalCommand    = NotifyCriticalCheck.IsChecked == true;
        _settings.CadenceGovernor.Enabled    = CoalesceNotifyCheck.IsChecked == true;
        _settings.IdleThresholdScaling.Enabled = ScaleIdleCheck.IsChecked == true;
        _settings.OsEventLog.Enabled         = OsEventLogCheck.IsChecked == true;
        _settings.EventLogPersist            = PersistLogCheck.IsChecked == true;
        _settings.MonitorAllProcesses        = MonitorAllCheck.IsChecked == true;
        _settings.IdleCleanupEnabled         = IdleCleanupCheck.IsChecked == true;
        _settings.IdleCleanupAfterMinutes    = idleAfter;
        _settings.AdbBridge.Enabled          = adbEnabled;
        _settings.AdbBridge.ExecutablePath   = string.IsNullOrWhiteSpace(adbPath) ? null : Path.GetFullPath(adbPath);
        _settings.AdbBridge.ExecutableSha256 = adbHash;
        _settings.AdbBridge.EnrolledDeviceSerials = adbDevices;

        _settings.AlertLevelMediumCount      = alertMed;
        _settings.AlarmLevelHighCount        = alarmHigh;
        _settings.AlarmLevelUniqueRules      = alarmRules;
        _settings.AlarmLevelCategories       = alarmCats;
        _settings.EmergencyLevelTotalAlerts  = emergencyTotal;
        _settings.EmergencyRuleIds           = emergencyRules;

        // Automatic responses (live: the runner holds this same settings instance, so no restart needed).
        _settings.AlertResponses.OnAlert     = Compose(AlertAskCheck, null, AlertCleanupCheck);   // no Alert audit
        _settings.AlertResponses.OnAlarm     = Compose(AlarmAskCheck, AlarmAuditCheck, AlarmCleanupCheck);
        _settings.AlertResponses.OnEmergency = Compose(EmergencyAskCheck, EmergencyAuditCheck, EmergencyCleanupCheck);
        _settings.AlertResponses.CooldownMinutes = arCooldown;
        _settings.ScheduledAudit.Enabled = ScheduledAuditCheck.IsChecked == true;
        _settings.ScheduledAudit.EveryNEvents = auditEvery;
        _settings.ScheduledAudit.IntervalMinutes = auditInterval;
        _settings.ScheduledAudit.CooldownMinutes = auditCooldown;

        // Game mode (live: the tray watcher reads this same settings instance).
        _settings.GameMode.Enabled                   = GameModeCheck.IsChecked == true;
        _settings.GameMode.AllowCriticalBreakThrough = GameModeBreakThroughCheck.IsChecked == true;

        ApplyDecoyCredentials();

        SettingsStore.Save(_settings);

        // ── Start with Windows (registry, not settings JSON) ─────────────────
        var startupWanted = StartWithWindowsCheck.IsChecked == true;
        string? startupFailureStatus = null;
        try
        {
            if (startupWanted != StartupManager.IsEnabled())
                StartupManager.SetEnabled(startupWanted);

            // If they just enabled it from a drive that may be absent at sign-in (removable / network / a
            // secondary disk like W:), say so now — that's the silent "didn't start at boot" trap.
            if (startupWanted && StartupManager.GetDriveWarning() is { } warn)
                MessageBox.Show(warn, "TraceBrake — start with Windows",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            // Do not leave the checkbox or the final status claiming a change that Windows rejected. Re-read the
            // registry (the source of truth) so the UI immediately returns to the actual startup posture.
            var startupActuallyEnabled = StartupManager.IsEnabled();
            StartWithWindowsCheck.IsChecked = startupActuallyEnabled;
            startupFailureStatus = $"Settings saved; Windows startup remains {(startupActuallyEnabled ? "on" : "off")}.";
            MessageBox.Show($"Couldn't update the Windows startup entry: {ex.Message}", "TraceBrake",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        if (portChanged)
            MessageBox.Show("Port change takes effect after restart.", "TraceBrake",
                MessageBoxButton.OK, MessageBoxImage.Information);

        // Apply the elevation toggle (starts/stops the sidecar; enabling prompts UAC).
        if (runElevatedChanged)
            _onRunElevatedChanged?.Invoke(_settings.RunElevated);

        // Apply the MCP tool-scan toggle (starts/stops the opt-in outbound probe).
        if (scanMcpToolsChanged)
            _onScanMcpToolsChanged?.Invoke(_settings.ScanMcpTools);

        // Revocation/re-enrolment is live and atomic: the old executor and its pending actions are stopped before the
        // new binary/device set is armed. The Saved confirmation therefore describes current runtime state.
        if (adbChanged)
            _onAdbBridgeChanged?.Invoke();

        // Hosted as a tab (no window to close) — confirm in place instead.
        SavedStatus.Text = startupFailureStatus ?? "Saved.";
    }

    private void BrowseAdbClick(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Choose Android SDK adb.exe",
            Filter = "Android Debug Bridge (adb.exe)|adb.exe|Executables (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };
        if (Path.IsPathFullyQualified(AdbPathBox.Text) && File.Exists(AdbPathBox.Text))
            dialog.InitialDirectory = Path.GetDirectoryName(AdbPathBox.Text);
        if (dialog.ShowDialog() == true)
        {
            AdbPathBox.Text = dialog.FileName;
            AdbStatusText.Text = "Path selected. Save to enrol it, or use Test and list devices.";
        }
    }

    private async void ProbeAdbClick(object sender, RoutedEventArgs e)
    {
        var path = AdbPathBox.Text.Trim();
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
        {
            AdbStatusText.Text = "Choose an existing adb executable first.";
            return;
        }
        string hash;
        try { hash = Foreman.Core.ComputerUse.AdbProcessRunner.ComputeSha256(path); }
        catch (Exception ex)
        {
            AdbStatusText.Text = $"Could not hash-pin adb.exe: {ex.Message}";
            return;
        }
        var alreadyEnrolled =
            string.Equals(_settings.AdbBridge.ExecutablePath, path, StringComparison.OrdinalIgnoreCase)
            && string.Equals(_settings.AdbBridge.ExecutableSha256, hash, StringComparison.OrdinalIgnoreCase);
        if (!alreadyEnrolled
            && !await Foreman.App.Security.PresenceGuard.AuthorizeAsync(
                Foreman.Core.Security.WeakeningAction.EnrollAdbBridge,
                $"probe ADB executable '{path}'",
                forcePresence: true, freshTap: true))
        {
            AdbStatusText.Text = "Probe cancelled: presence was not verified.";
            return;
        }

        AdbStatusText.Text = "Checking...";
        using var runner = new Foreman.Core.ComputerUse.AdbProcessRunner(path, hash);
        var result = await runner.RunAsync(["devices", "-l"], 256 * 1024, TimeSpan.FromSeconds(15));
        if (result.ExitCode != 0)
        {
            AdbStatusText.Text = string.IsNullOrWhiteSpace(result.StandardError)
                ? $"adb exited with code {result.ExitCode}."
                : result.StandardError.Trim();
            return;
        }
        var lines = System.Text.Encoding.UTF8.GetString(result.StandardOutput)
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Skip(1)
            .Where(line => !line.TrimStart().StartsWith("*", StringComparison.Ordinal))
            .ToArray();
        AdbStatusText.Text = lines.Length == 0
            ? "adb is available; no devices are connected."
            : $"{lines.Length} device(s): {string.Join(" | ", lines.Select(line => line.Trim()))}";
    }

    private static string? DiscoverAdbPath()
    {
        var roots = new[]
        {
            Environment.GetEnvironmentVariable("ANDROID_SDK_ROOT"),
            Environment.GetEnvironmentVariable("ANDROID_HOME"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Android", "Sdk"),
        };
        return roots
            .Where(static root => !string.IsNullOrWhiteSpace(root))
            .Select(static root => Path.Combine(root!, "platform-tools", "adb.exe"))
            .FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// Plants / removes decoy credentials per the toggle. Gaps-only (never shadows a real file) and
    /// sentinel-gated (never deletes a real file). A slot the user reclaimed for real credentials is
    /// auto-retired first. Re-plants on each save so a changed canarytoken is applied.
    /// </summary>
    private void ApplyDecoyCredentials()
    {
        var dc = _settings.DecoyCredentials;
        var wasEnabled = dc.Enabled;
        var wasAuditing = dc.Enabled && dc.EnableReadAuditing;
        var wasCanary = (dc.IncludeAwsCanaryToken, dc.AwsCanaryAccessKeyId, dc.AwsCanarySecretAccessKey);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        // Snapshot the audited path set BEFORE any change so we can re-apply the sidecar iff it actually changes.
        var wasAuditPaths = wasAuditing
            ? DecoyCredentialPolicy.ReadAuditPaths(home, dc.PlantedPaths)
            : (IReadOnlyList<string>)[];

        dc.Enabled                   = DecoyCredsCheck.IsChecked == true;
        dc.EnableReadAuditing        = DecoyReadAuditCheck.IsChecked == true;
        dc.IncludeAwsCanaryToken     = DecoyAwsCanaryCheck.IsChecked == true;
        dc.AwsCanaryAccessKeyId      = string.IsNullOrWhiteSpace(DecoyAwsKeyIdBox.Text)  ? null : DecoyAwsKeyIdBox.Text.Trim();
        dc.AwsCanarySecretAccessKey  = string.IsNullOrWhiteSpace(DecoyAwsSecretBox.Text) ? null : DecoyAwsSecretBox.Text.Trim();

        // Re-plant only when content/placement could actually differ (enabled flip or canary change) — an
        // unrelated Settings save must not churn files/SACLs or pop a "Planted N" dialog.
        var contentChanged = dc.Enabled != wasEnabled
            || (dc.IncludeAwsCanaryToken, dc.AwsCanaryAccessKeyId, dc.AwsCanarySecretAccessKey) != wasCanary;

        try
        {
            var mgr = new DecoyCredentialManager(new SystemDecoyFileSystem());
            var reval = mgr.Revalidate(dc.PlantedPaths);   // retire slots reclaimed for real credentials (never deleted)

            if (dc.Enabled && contentChanged)
            {
                mgr.Remove(reval.StillDecoys);             // clear our own decoys so re-plant reflects current settings
                var plant = mgr.Plant(dc);
                dc.PlantedPaths = plant.Planted.ToList();
                var retired = reval.Reclaimed.Count > 0
                    ? $"  Retired {reval.Reclaimed.Count} slot(s) you reclaimed for real credentials (left untouched)." : "";
                MessageBox.Show(
                    $"Planted {plant.Planted.Count} decoy credential file(s); skipped {plant.SkippedExisting.Count} path(s) you already use.{retired}",
                    "TraceBrake — Decoy credentials", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else if (dc.Enabled)
            {
                // Already enabled, nothing decoy-related changed: keep the planted decoys, just stop tracking
                // any slot the user reclaimed for real credentials (so its SACL is dropped on re-apply below).
                dc.PlantedPaths = reval.StillDecoys.ToList();
            }
            else
            {
                var removed = mgr.Remove(reval.StillDecoys);
                dc.PlantedPaths = [];
                if (wasEnabled)
                    MessageBox.Show($"Removed {removed.Count} decoy credential file(s).",
                        "TraceBrake — Decoy credentials", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Couldn't update decoy credentials: {ex.Message}",
                "TraceBrake", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        // B9 polish: arm the (possibly just-minted) per-install decoy sentinel for cred-040 detection, live — no restart.
        Foreman.Core.Heuristics.CommandAnalyzer.DecoySentinelToken = dc.InstanceSentinel;

        // Re-apply the elevated auditor whenever the AUDITED PATH SET changed — enable/disable, a reclaimed
        // slot, or a re-plant that added/removed bait — not just when the on/off boolean flipped. Otherwise the
        // sidecar can keep a stale SACL on a path the user just reclaimed for real credentials. UAC re-prompts
        // only on a genuine change (an unrelated save leaves the set identical → no prompt).
        var nowAuditPaths = (dc.Enabled && dc.EnableReadAuditing)
            ? DecoyCredentialPolicy.ReadAuditPaths(home, dc.PlantedPaths)
            : (IReadOnlyList<string>)[];
        if (!AuditSetEqual(wasAuditPaths, nowAuditPaths))
            _onDecoyAuditChanged?.Invoke();
    }

    private static bool AuditSetEqual(IReadOnlyList<string> a, IReadOnlyList<string> b)
        => a.Count == b.Count && new HashSet<string>(a, StringComparer.OrdinalIgnoreCase).SetEquals(b);

    // Revert discards unsaved edits by re-reading the saved settings back into the controls (in place; there is no
    // window to close). The presence lock + guardian buttons already act immediately, so they need no revert.
    private void RevertClick(object sender, RoutedEventArgs e)
    {
        Populate();
        RefreshPresenceLock();
        RefreshGuardian();
        SavedStatus.Text = "Reverted unsaved changes.";
    }

    /// <summary>Re-read settings into the controls when the tab is shown, so it reflects changes made elsewhere.</summary>
    public void RefreshState()
    {
        Populate();
        RefreshPresenceLock();
        RefreshGuardian();
        SavedStatus.Text = string.Empty;
    }
}
