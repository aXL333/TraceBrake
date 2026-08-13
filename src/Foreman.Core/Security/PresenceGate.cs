namespace Foreman.Core.Security;

/// <summary>A gate decision, for the operator log — a DENIED weakening attempt is itself a signal worth recording.</summary>
public sealed record PresenceDecision(bool Granted, WeakeningAction Action, string Detail, string? AuthenticatorLabel);

/// <summary>
/// Wraps <see cref="PresenceLockPolicy"/> + an <see cref="IPresenceVerifier"/> into the runtime gate that
/// actually guards weakening actions. <b>FAIL-CLOSED</b>: when presence is required, the action proceeds ONLY
/// on a verified tap — a user cancel, an auth failure, a missing/unenrolled authenticator, or a verifier error
/// all BLOCK. Every gated decision (granted or denied) is reported via <c>onDecision</c> so a denied attempt is
/// recorded, never silent. A short approval-TTL caches a recent tap so rapid follow-up actions don't each
/// prompt (mitigates Strict's friction). The policy + fail-closed semantics are unit-tested here with a fake
/// verifier; the live WebAuthn prompt is the app-layer part.
/// </summary>
public sealed class PresenceGate
{
    /// <summary>
    /// Hard ceiling on the approval cache (B9 polish): however high the operator sets ApprovalTtlSeconds, a cached
    /// tap expires within this window, so an old approval can't be replayed to keep weakening TraceBrake indefinitely
    /// — there's always a re-tap at least this often. 5 minutes balances Strict-mode friction against staleness.
    /// </summary>
    public const int MaxApprovalTtlSeconds = 300;

    private readonly Func<PresenceLockSettings> _settings;
    private readonly IPresenceVerifier _verifier;
    private readonly Action<PresenceDecision> _onDecision;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _lock = new();
    // Keyed by (action, detail) so a tap for one change never silently covers a DIFFERENT one (closes the
    // "one tap covers bind+enroll+resume" finding). The CU-sovereignty actions additionally pass freshTap and never
    // read or write this cache at all.
    private readonly Dictionary<string, DateTimeOffset> _approvals = new();

    public PresenceGate(
        Func<PresenceLockSettings> settings,
        IPresenceVerifier verifier,
        Action<PresenceDecision> onDecision,
        Func<DateTimeOffset>? now = null)
    {
        _settings = settings;
        _verifier = verifier;
        _onDecision = onDecision;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// True to PROCEED with the action, false to BLOCK it. Non-gated actions (lock off, or action not in scope)
    /// proceed silently without a prompt. <paramref name="detail"/> describes the specific change for the audit record.
    /// <paramref name="forcePresence"/> (the CU-sovereignty actions: bind / enroll-local-agent / resume) demands a
    /// verified tap REGARDLESS of the lock being off or the action being out of the normal gated set - the
    /// "lock off => proceed" / "not gated => proceed" branches do NOT apply (spec INV-16). <paramref name="freshTap"/>
    /// bypasses the approval cache entirely so each such action needs its own fresh tap.
    /// </summary>
    public async Task<bool> AuthorizeAsync(WeakeningAction action, string detail,
        bool forcePresence = false, bool freshTap = false, CancellationToken ct = default)
    {
        var s = _settings();
        if (!forcePresence && !PresenceLockPolicy.RequiresPresence(action, s)) return true;

        var key = $"{(int)action}|{detail}";
        // A recent successful tap for THIS (action, detail) covers rapid follow-ups within the window - but never
        // longer than MaxApprovalTtlSeconds, and never for a freshTap action (each demands its own tap).
        if (!freshTap && s.ApprovalTtlSeconds > 0)
        {
            var ttl = Math.Min(s.ApprovalTtlSeconds, MaxApprovalTtlSeconds);
            lock (_lock)
            {
                if (_approvals.TryGetValue(key, out var when) && _now() - when < TimeSpan.FromSeconds(ttl))
                {
                    Report(true, action, detail + " (within approval window)", null);
                    return true;
                }
            }
        }

        if (string.IsNullOrEmpty(s.CredentialId))
        {
            // Nothing enrolled => cannot prompt. Fail CLOSED: a misconfiguration (or a forced CU action with no
            // enrolled credential, INV-16) must not become a bypass.
            Report(false, action, detail + " - no authenticator enrolled", null);
            return false;
        }

        // Touch-only (user presence) is the default; full user verification (PIN/biometric) is demanded when the
        // operator opted in globally OR the action is a desktop-input-authority / panic-override one (forced in code).
        var requireUv = s.RequireUserVerification || PresenceLockPolicy.ForcesUserVerification(action);

        PresenceResult r;
        try
        {
            r = await _verifier.VerifyAsync(s.CredentialId, PromptReason(action), requireUv, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Report(false, action, detail + $" - verifier error ({ex.GetType().Name})", null);   // fail closed
            return false;
        }

        if (r.Verified && !freshTap)
            lock (_lock) { _approvals[key] = _now(); }

        Report(r.Verified, action, r.Verified ? detail : detail + $" - {r.FailureReason}", r.AuthenticatorLabel);
        return r.Verified;
    }

    private void Report(bool granted, WeakeningAction action, string detail, string? label)
    {
        try { _onDecision(new PresenceDecision(granted, action, detail, label)); }
        catch { /* logging a decision must never break the gate */ }
    }

    private static string PromptReason(WeakeningAction action) => action switch
    {
        WeakeningAction.LowerTrust           => "Authorize raising a harness's Trust level (fewer restrictions)",
        WeakeningAction.MuteProtectedAlert   => "Authorize muting a protected alert",
        WeakeningAction.DisableMonitoring    => "Authorize disabling monitoring of a harness",
        WeakeningAction.DisableReadAuditing  => "Authorize disabling credential read-auditing",
        WeakeningAction.DisableLogPersist    => "Authorize disabling the persistent log",
        WeakeningAction.ClearOrRotateLog     => "Authorize clearing the event log",
        WeakeningAction.EditHarnessSysprompt => "Authorize editing a harness's modalities",
        WeakeningAction.ResumeComputerUse    => "Authorize resuming computer use after a panic stop",
        WeakeningAction.BindCuWindow         => "Authorize binding this window for AI computer use",
        WeakeningAction.EnrollLocalAgentHost => "Authorize a local AI agent to drive the desktop",
        WeakeningAction.ExitForeman          => "Authorize quitting TraceBrake",
        _                                    => "Authorize a TraceBrake security change",
    };
}
