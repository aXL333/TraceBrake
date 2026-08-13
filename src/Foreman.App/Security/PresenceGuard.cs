using Foreman.Core.Events;
using Foreman.Core.Models;
using Foreman.Core.Security;
using Foreman.Core.Settings;

namespace Foreman.App.Security;

/// <summary>
/// App-side singleton that arms the <see cref="PresenceGate"/> and exposes it to UI handlers without threading
/// it through every window constructor. It routes every gate decision to the event log — a DENIED weakening
/// attempt is a visible signal, not a silent no-op — and owns enroll/disable so that arming the lock proves the
/// authenticator works, and DISARMING it is itself a presence tap (an agent can't one-click un-gate). The
/// verifier is Windows Hello today; the webauthn.dll key picker (YubiKey/FIDO2/U2F) swaps in behind the same
/// gate with no change to callers.
/// </summary>
public static class PresenceGuard
{
    // WebAuthn picker (Hello + YubiKey/FIDO2/U2F) when available, platform-only Hello as fallback; verification
    // routes by the pinned credential id. The gate + every wired site are unchanged behind this seam.
    private static readonly IPresenceVerifier _verifier = new CompositePresenceVerifier();
    private static PresenceGate? _gate;
    private static ForemanSettings? _settings;

    public static IPresenceVerifier Verifier => _verifier;
    public static bool IsAvailable => _verifier.IsAvailable;
    public static bool IsEnabled => _settings?.PresenceLock.Enabled == true;
    public static string? AuthenticatorLabel => _settings?.PresenceLock.AuthenticatorLabel;

    public static void Configure(ForemanSettings settings, EventBus bus)
    {
        _settings = settings;
        _gate = new PresenceGate(
            () => settings.PresenceLock,
            _verifier,
            d => bus.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow,
                d.Granted ? ForemanSeverity.Info : ForemanSeverity.Medium,
                "Foreman.PresenceLock",
                d.Granted
                    ? $"Presence authorized — {Describe(d.Action)}: {d.Detail}" + (d.AuthenticatorLabel is { } l ? $" [{l}]" : "")
                    : $"Presence DENIED — {Describe(d.Action)} blocked: {d.Detail}")));
    }

    /// <summary>
    /// True to PROCEED with a weakening action, false to BLOCK it. Safe before <see cref="Configure"/> (proceeds)
    /// and when the lock is off (proceeds silently). <paramref name="detail"/> goes into the audit record.
    /// </summary>
    public static async Task<bool> AuthorizeAsync(WeakeningAction action, string detail,
        bool forcePresence = false, bool freshTap = false)
    {
        // Not configured yet: normal actions proceed; a FORCED CU-sovereignty action fails CLOSED (we cannot verify a
        // tap, so we must not silently permit binding / enrolling / resuming desktop CU). (INV-16)
        if (_gate is null) return !forcePresence;
        return await _gate.AuthorizeAsync(action, detail, forcePresence, freshTap).ConfigureAwait(false);
    }

    /// <summary>Enroll + arm the lock: confirm a tap works, pin the credential, persist. Returns (ok, message).</summary>
    public static async Task<(bool Ok, string Message)> EnableAsync(LockScope scope)
    {
        if (_settings is null) return (false, "Presence lock not initialized.");
        var enroll = await _verifier.EnrollAsync(
            "Enroll this device to authorize TraceBrake's security-weakening actions",
            _settings.PresenceLock.RequireUserVerification).ConfigureAwait(false);
        if (!enroll.Ok) return (false, enroll.FailureReason ?? "Enrollment failed.");

        var s = _settings.PresenceLock;
        s.Enabled = true;
        s.Scope = scope;
        s.CredentialId = enroll.CredentialId;
        s.AuthenticatorLabel = enroll.AuthenticatorLabel;
        SettingsStore.Save(_settings);
        return (true, $"Presence lock armed via {enroll.AuthenticatorLabel}.");
    }

    /// <summary>
    /// Disarm the lock — itself a presence tap when armed (turning the lock off is the ultimate weakening, so it
    /// can't be a one-click escape). Recovery from a lost authenticator is editing settings.json. Returns (ok, message).
    /// </summary>
    public static async Task<(bool Ok, string Message)> DisableAsync()
    {
        if (_settings is null) return (false, "Presence lock not initialized.");
        var s = _settings.PresenceLock;
        if (s.Enabled && !string.IsNullOrEmpty(s.CredentialId))
        {
            PresenceResult r;
            // Disabling the lock entirely is the ultimate weakening, so demand full verification, not just a touch.
            try { r = await _verifier.VerifyAsync(s.CredentialId, "Authorize disabling the presence lock", requireUserVerification: true).ConfigureAwait(false); }
            catch { return (false, "Verifier error — lock stays armed."); }
            if (!r.Verified) return (false, "Presence not verified — lock stays armed.");
        }
        s.Enabled = false;
        SettingsStore.Save(_settings);
        return (true, "Presence lock disarmed.");
    }

    private static string Describe(WeakeningAction a) => a switch
    {
        WeakeningAction.LowerTrust           => "raise Trust / loosen its profile",
        WeakeningAction.MuteProtectedAlert   => "mute a protected alert",
        WeakeningAction.DisableMonitoring    => "disable harness monitoring",
        WeakeningAction.DisableReadAuditing  => "disable read-auditing",
        WeakeningAction.DisableLogPersist    => "disable persistent logging",
        WeakeningAction.ClearOrRotateLog     => "clear the log",
        WeakeningAction.EditHarnessSysprompt => "edit harness modalities",
        WeakeningAction.ResumeComputerUse    => "resume computer use after a panic stop",
        WeakeningAction.BindCuWindow         => "bind a window for AI computer use",
        WeakeningAction.EnrollLocalAgentHost => "authorize a local AI agent to drive the desktop",
        WeakeningAction.EnrollAdbBridge      => "authorize the Android ADB bridge and enrolled devices",
        WeakeningAction.ExitForeman          => "quit TraceBrake",
        _                                    => "security change",
    };
}
