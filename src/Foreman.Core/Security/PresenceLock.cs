namespace Foreman.Core.Security;

/// <summary>
/// The watchdog-weakening actions a rogue or prompt-injected agent would use to blind TraceBrake or erase its
/// tracks. The presence lock (P3) makes the gated ones require a hardware user-presence tap (Windows
/// Hello/PIN, passkey, YubiKey, U2F) — the one thing a same-user process can't satisfy programmatically.
/// </summary>
public enum WeakeningAction
{
    LowerTrust,
    MuteProtectedAlert,
    DisableMonitoring,
    DisableReadAuditing,    // decoys / SACL read-auditing
    DisableLogPersist,
    ClearOrRotateLog,
    EditHarnessSysprompt,
    RelaxHarnessCapabilityRestriction,
    ResumeComputerUse,      // un-halt TraceBrake-mediated computer/browser use after a panic STOP
    BindCuWindow,           // bind the desktop CU target window (operator gesture; spec INV-10/INV-17)
    EnrollLocalAgentHost,   // authorize a local AI agent to drive desktop CU (spec INV-16)
    EnrollAdbBridge,        // authorize an adb executable + external Android device set
    ApproveCuSensitiveAction, // approve a HELD desktop/Android CU action - fresh tap, not just operator token (INV-16)
    ResolveVaultCredential, // release a stored credential/2FA into agent-driven CU/BU - a fresh tap per resolution
    SelfSignupVaultCredential, // agent self-signup: CREATE + store a NEW credential for the live origin (a vault WRITE)
    ExitForeman,
}

/// <summary>How much the presence lock gates. Strict additionally gates quitting Foreman.</summary>
public enum LockScope { Standard, Strict }

/// <summary>
/// Presence-lock configuration. Off until the user enrolls a hardware authenticator (P3 enrollment, which
/// pins the credential). C3 (user, 2026-06-12): default Standard; Strict is opt-in and the UI must warn that
/// gating Exit is annoying. <see cref="ApprovalTtlSeconds"/> &gt; 0 caches an approval so rapid actions don't
/// each prompt (mitigates Strict's friction); 0 = tap every time.
/// </summary>
public sealed class PresenceLockSettings
{
    public bool Enabled { get; set; } = false;
    public LockScope Scope { get; set; } = LockScope.Standard;
    public int ApprovalTtlSeconds { get; set; } = 0;

    /// <summary>
    /// The enrolled authenticator's credential id (base64url), pinned at enrollment. The presence prompt
    /// asserts THIS credential — Windows Hello (platform: PIN/face/fingerprint) or a roaming FIDO2/U2F key
    /// (YubiKey), whichever the user enrolled; Windows' WebAuthn picker covers all of them. Empty until
    /// enrolled — the gate then has nothing to prompt and fails closed. (Recovery from a lost authenticator is
    /// editing this file, the same-user boundary the threat model already concedes.)
    /// </summary>
    public string? CredentialId { get; set; }

    /// <summary>Friendly label of the enrolled authenticator for the UI ("Windows Hello", "Security key"). Cosmetic.</summary>
    public string? AuthenticatorLabel { get; set; }

    /// <summary>
    /// When true, every presence assertion demands full user VERIFICATION (a FIDO2 PIN or biometric), not just
    /// user PRESENCE (a touch). Default FALSE = touch-only (WebAuthn user-verification DISCOURAGED): a roaming
    /// FIDO2/U2F key (YubiKey) needs only a single touch, no PIN prompt. Touch alone already stops the rogue-agent
    /// threat (software cannot touch a physical key); UV only adds physical-key-theft hardening, for operators who
    /// opt in. NB: the platform authenticator (Windows Hello) always verifies fully regardless — this setting only
    /// changes roaming keys. Deliberately NOT part of the settings seal: a silent flip to touch-only cannot help a
    /// rogue agent (it still can't touch the key), so sealing it would only buy a false tamper verdict on upgrade.
    /// </summary>
    public bool RequireUserVerification { get; set; } = false;
}

/// <summary>
/// Pure decision: does an action require a presence tap, given the lock config? Unit-tested. The actual
/// WebAuthn prompt + the action-interception wiring are the runtime/live-verified parts.
/// </summary>
public static class PresenceLockPolicy
{
    // The Standard set — always gated when the lock is on (C3). Exit is handled separately (Strict only).
    private static readonly HashSet<WeakeningAction> StandardGated =
    [
        WeakeningAction.LowerTrust,
        WeakeningAction.MuteProtectedAlert,
        WeakeningAction.DisableMonitoring,
        WeakeningAction.DisableReadAuditing,
        WeakeningAction.DisableLogPersist,
        WeakeningAction.ClearOrRotateLog,
        WeakeningAction.EditHarnessSysprompt,
        WeakeningAction.RelaxHarnessCapabilityRestriction,
        WeakeningAction.ResumeComputerUse,
        WeakeningAction.BindCuWindow,
        WeakeningAction.EnrollLocalAgentHost,
        WeakeningAction.EnrollAdbBridge,
        WeakeningAction.ApproveCuSensitiveAction,
        WeakeningAction.ResolveVaultCredential,
        WeakeningAction.SelfSignupVaultCredential,
    ];

    public static bool RequiresPresence(WeakeningAction action, PresenceLockSettings settings)
    {
        if (!settings.Enabled) return false;                                  // lock off → nothing gated
        if (action == WeakeningAction.ExitForeman) return settings.Scope == LockScope.Strict;
        return StandardGated.Contains(action);
    }

    // These actions grant durable desktop-input authority, CREATE a durable credential, or override the operator's own
    // panic STOP. They ALWAYS demand full user VERIFICATION (PIN/biometric) where the key supports it, even when the
    // global default is touch-only — "a human deliberately did this; prove it's the SAME human." Hardcoded (not a
    // settings field) so a settings.json edit can't downgrade them. PREFERRED degrades to touch on a PIN-less key,
    // so this costs nothing there; it only adds the PIN prompt on exactly the highest-stakes actions.
    private static readonly HashSet<WeakeningAction> ForcedUserVerification =
    [
        WeakeningAction.ResumeComputerUse,
        WeakeningAction.BindCuWindow,
        WeakeningAction.EnrollLocalAgentHost,
        WeakeningAction.EnrollAdbBridge,
        WeakeningAction.ApproveCuSensitiveAction,
        WeakeningAction.SelfSignupVaultCredential, // a vault WRITE that mints a new credential - the highest-stakes vault op
    ];

    /// <summary>
    /// True if <paramref name="action"/> must use full user verification (PIN/biometric) regardless of the global
    /// touch-only default — the desktop-input-authority grants and the panic-resume override. The vault-release and
    /// ordinary weakening taps are NOT here: they follow <see cref="PresenceLockSettings.RequireUserVerification"/>
    /// (default touch-only), since their dominant threat is remote software (which can't touch a key at all).
    /// </summary>
    public static bool ForcesUserVerification(WeakeningAction action) => ForcedUserVerification.Contains(action);
}
