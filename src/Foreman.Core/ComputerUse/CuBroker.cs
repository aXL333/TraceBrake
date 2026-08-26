using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Security.Cryptography;
using Foreman.Core.Settings;

namespace Foreman.Core.ComputerUse;

/// <summary>Lifecycle of a brokered computer-use action. The executor only ever runs APPROVED actions, so nothing
/// touches the machine until the auditor (and, for a Held action, the operator) clears it.</summary>
public enum CuActionState
{
    Auditing,   // submitted; the auditor is judging it
    Held,       // auditor said Hold — awaiting an operator approve/reject
    Approved,   // cleared to execute (auditor Allow, or operator approved a Held action)
    Rejected,   // operator rejected a Held action
    Blocked,    // auditor Block, or submitted while halted — never executes
    Executing,  // claimed by the executor (extension / sidecar)
    Completed,
    Failed,
}

/// <summary>One action moving through the broker.</summary>
public sealed record CuBrokerItem(
    string ActionId,
    CuAction Action,
    CuActionState State,
    CuVerdict? Verdict,
    DateTimeOffset CreatedAt,
    object? Result = null,
    string? Error = null,
    DateTimeOffset? UpdatedAt = null,
    // True once the OPERATOR has explicitly approved this action out of Held. The delivery-time focus re-gate
    // skips operator-approved items so an excursion the operator already OK'd isn't re-held into a loop.
    bool OperatorApproved = false,
    // Desktop one-window confinement: the active-window Epoch this item was bound at (null for browser), and the
    // panic epoch at submit. Claim re-checks both, so a window switch/rebind or a panic since approval invalidates it.
    long? BoundEpoch = null,
    long PanicEpoch = 0,
    // A claim is a capability, not merely a state flip. Only the executor that received this unguessable lease may
    // resolve secrets for, or complete, the action. The lease is cleared by panic/revocation/expiry.
    string? ExecutionOwner = null,
    string? ExecutionToken = null);

/// <summary>Hard broker resource/lifetime limits. Non-terminal work is capped separately because terminal-only
/// pruning cannot contain a compromised harness that deliberately fills Held/Auditing/Executing states.</summary>
public sealed record CuBrokerOptions
{
    public int MaxItems { get; init; } = 200;
    public int MaxNonTerminalItems { get; init; } = 100;
    public int MaxNonTerminalPerHarness { get; init; } = 25;
    public TimeSpan AuditingTtl { get; init; } = TimeSpan.FromMinutes(2);
    public TimeSpan HeldTtl { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan ApprovedTtl { get; init; } = TimeSpan.FromMinutes(2);
    public TimeSpan ExecutingTtl { get; init; } = TimeSpan.FromMinutes(10);
}

/// <summary>
/// The mediated computer-use command broker — the Phase 0.5 replacement for LiveWeave's immediate command queue.
/// Where LiveWeave was Pending -> Delivered -> Completed (accepted commands ran at once), every action here passes
/// an AUDIT gate first and the executor only ever claims APPROVED actions:
///
///   Submit -> Auditing -> (Approved | Held | Blocked)
///   Held   -> [operator] -> Approved | Rejected
///   Approved -> Claim -> Executing -> Completed | Failed
///
/// The panic kill plugs straight in: while halted, Submit is Blocked and Claim delivers nothing, so the executor
/// goes quiet instantly. The auditor is the Phase 2 <see cref="AuditPipeline"/> (fast-path + optional cloud judge);
/// an auditor error fails CLOSED to Held (operator decides), never to a silent Allow.
/// </summary>
public sealed class CuBroker
{
    private readonly ConcurrentDictionary<string, CuBrokerItem> _items = new();
    private readonly IAuditor _auditor;
    private readonly Func<bool> _isHalted;
    private readonly CuBrokerOptions _options;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly object _maintenanceLock = new();

    // Operator-chosen driver SET: empty = operator only, ["*"] = any harness, else the specific harness ids that
    // may drive. Volatile reference; SetDrivers swaps the whole array atomically. (Was a single string; now a set
    // so the operator can authorize e.g. {claude-code, codex} without opening it to every harness.)
    private volatile string[] _drivers = [];
    private const string OperatorMarker = "operator";

    /// <summary>
    /// App-wired universal Trust policy. Null preserves the legacy broker defaults for tests/headless hosts. The
    /// callback is re-evaluated at delivery so a session lock or live policy edit cannot leave stale authority.
    /// </summary>
    public Func<CuAction, TrustCapabilityDecision>? CapabilityGate { get; set; }

    // Operator's pinned shared-attention tab (browser): the locked focus the extension reports when the operator
    // presses the pinned icon. Null = no pin. Drives the excursion gate in SubmitAsync.
    private volatile string? _attentionTab;

    // Desktop one-window-at-a-time confinement (parallel to the browser pin; modality-scoped). The operator binds a
    // single target window; _windowEpoch bumps on every (re)bind so an action approved against an old binding is
    // caught at delivery; _panicEpoch bumps on each halt so actions queued before a panic are invalidated.
    private volatile CuWindowRef? _activeWindow;
    private long _windowEpoch;
    private long _panicEpoch;

    // Per-harness action rate limit (token bucket): a burst faster than a human could plausibly pilot is Held, not
    // run (Slice 2 -- approval-fatigue + auditor-flood defense). The operator's own manual actions are exempt.
    private readonly object _rateLock = new();
    private readonly Dictionary<string, (double Tokens, long Ticks)> _rate = new();
    private const double RateBurst = 12;
    private const double RatePerSecond = 6;

    public CuBroker(IAuditor auditor, Func<bool>? isHalted = null,
        CuBrokerOptions? options = null, Func<DateTimeOffset>? utcNow = null)
    {
        _auditor = auditor ?? throw new ArgumentNullException(nameof(auditor));
        _isHalted = isHalted ?? (() => false);
        _options = options ?? new CuBrokerOptions();
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        if (_options.MaxItems < 1) throw new ArgumentOutOfRangeException(nameof(options), "MaxItems must be positive.");
        if (_options.MaxNonTerminalItems is < 1 || _options.MaxNonTerminalItems > _options.MaxItems)
            throw new ArgumentOutOfRangeException(nameof(options), "MaxNonTerminalItems must be within MaxItems.");
        if (_options.MaxNonTerminalPerHarness is < 1 || _options.MaxNonTerminalPerHarness > _options.MaxNonTerminalItems)
            throw new ArgumentOutOfRangeException(nameof(options), "MaxNonTerminalPerHarness must be within the global non-terminal cap.");
        if (_options.AuditingTtl <= TimeSpan.Zero || _options.HeldTtl <= TimeSpan.Zero
            || _options.ApprovedTtl <= TimeSpan.Zero || _options.ExecutingTtl <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(options), "Computer-use TTLs must be positive.");
    }

    // ── Submit + audit ─────────────────────────────────────────────────────────

    /// <summary>Submit an action. Audits it (fail-closed to Held on error) and lands it in Approved/Held/Blocked.
    /// Returns the resulting item. While the panic halt is on, the action is Blocked without auditing.</summary>
    public async Task<CuBrokerItem> SubmitAsync(CuAction action, CuContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(context);

        var id = NewActionId();
        if (!string.IsNullOrWhiteSpace(action.ActionId))
        {
            var requested = action.ActionId.Trim();
            if (!IsValidActionId(requested))
                return BlockAndRecord(id, action with { ActionId = id }, "invalid action id",
                    "Action id must be 1-64 ASCII letters, digits, '_' or '-'.");
            id = requested;
        }

        if (!TrySnapshotAction(action, id, out action, out var snapshotError))
            return BlockAndRecord(id, action with { ActionId = id }, "invalid action envelope", snapshotError);

        if (_isHalted())
            return BlockAndRecord(id, action, "computer use is halted (panic)", "Computer use is halted.");

        // Desktop verb allowlist (INV-12 structural): reject an unknown/over-length verb before the auditor or the
        // injector ever sees it, so a crafted verb from a relayed proposal cannot smuggle through.
        if (action.Modality == CuModality.Desktop && !CuVerbs.IsKnownDesktop(action.Verb))
            return BlockAndRecord(id, action, "unsupported desktop verb", "Unsupported desktop verb.");

        if (action.Modality == CuModality.Browser && !CuVerbs.IsKnownBrowser(action.Verb))
            return BlockAndRecord(id, action, "unsupported browser verb", "Unsupported browser verb.");

        if (action.Modality == CuModality.Android && !CuVerbs.IsKnownAndroid(action.Verb))
            return BlockAndRecord(id, action, "unsupported Android/ADB verb", "Unsupported Android verb.");

        // Desktop/Android driver authorization. Desktop still requires an explicit id (never "*"); Android uses the
        // operator-approved shared driver set, so every selected harness can use the same unified cu_* surface.
        if (action.Modality is CuModality.Desktop or CuModality.Android
            && !CanDriveModality(action.ByHarness, isOperator: false, action.Modality))
            return BlockAndRecord(id, action,
                $"driver not authorized for {action.Modality.ToString().ToLowerInvariant()} computer use",
                "Driver not authorized for this modality.");

        if (action.Modality == CuModality.Android
            && !string.Equals(action.Verb, "devices", StringComparison.OrdinalIgnoreCase))
        {
            var serial = action.Arg("serial").Trim();
            lock (_enrollLock)
            {
                // QOL: when exactly one device is enrolled, a harness may omit serial; stamp the enrolled identity into
                // the audited action so the target is still explicit and immutable before approval/execution.
                if (serial.Length == 0 && _androidEnrollments.Count == 1)
                {
                    serial = _androidEnrollments.Single();
                    var stamped = new Dictionary<string, string>(action.Args, StringComparer.OrdinalIgnoreCase)
                    {
                        ["serial"] = serial,
                    };
                    action = action with { Args = stamped.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase) };
                }
                if (serial.Length == 0 || !_androidEnrollments.Contains(serial))
                    return BlockAndRecord(id, action, serial.Length == 0
                            ? "Android action requires an explicitly enrolled device serial"
                            : "target Android device is not enrolled",
                        "Target Android device is not enrolled.");
            }
        }

        TrustCapabilityDecision? trustDecision = null;
        if (!string.Equals(action.ByHarness, OperatorMarker, StringComparison.OrdinalIgnoreCase)
            && CapabilityGate is { } capabilityGate)
        {
            try { trustDecision = capabilityGate(action); }
            catch { trustDecision = new TrustCapabilityDecision(true, false, "Universal Trust policy could not be evaluated."); }
            if (trustDecision.Blocked)
                return BlockAndRecord(id, action, trustDecision.Reason, trustDecision.Reason);
        }

        // Rate limit (Slice 2): a non-operator harness flooding actions faster than a human could pilot is Held
        // without even auditing -- defeats approval-fatigue + auditor-flood. The operator's manual actions are exempt.
        if (!string.Equals(action.ByHarness, OperatorMarker, StringComparison.OrdinalIgnoreCase)
            && !RateLimitOk(action.ByHarness ?? "?"))
        {
            var now = _utcNow();
            var throttled = new CuBrokerItem(id, action, CuActionState.Held,
                CuVerdict.Hold("broker", "action rate exceeds plausible pilot speed — held for operator"),
                now, UpdatedAt: now,
                BoundEpoch: action.Modality == CuModality.Desktop ? _activeWindow?.Epoch : null,
                PanicEpoch: Interlocked.Read(ref _panicEpoch));
            TryAdmitNonTerminal(throttled, out var admitted);
            return admitted;
        }

        // APK approval is bound to the exact local file TraceBrake observed, not merely an agent-supplied path. This
        // happens after the harness rate gate (hashing can be expensive) but before auditing/approval. The executor
        // re-pins and re-verifies the canonical path + size + SHA-256 immediately before adb install.
        if (action.Modality == CuModality.Android
            && string.Equals(action.Verb, "install", StringComparison.OrdinalIgnoreCase))
        {
            var prepared = await AdbBridgeExecutor.PrepareInstallActionAsync(action, ct).ConfigureAwait(false);
            if (prepared.Action is null)
                return BlockAndRecord(id, action, prepared.Error ?? "APK preparation failed",
                    prepared.Error ?? "APK preparation failed.");
            if (!TrySnapshotAction(prepared.Action, id, out action, out snapshotError))
                return BlockAndRecord(id, action, "invalid prepared Android action", snapshotError);
        }

        // Capture the panic epoch at ADMISSION and stamp it on BOTH the Auditing placeholder and the final item. If a
        // panic bumps the epoch DURING the audit, the final item is stale (PanicEpoch < current) so Claim drops it - and
        // the CAS write-back below refuses to resurrect a placeholder OnPanicHalt already Rejected.
        var submitEpoch = Interlocked.Read(ref _panicEpoch);
        var admittedAt = _utcNow();
        var auditing = new CuBrokerItem(id, action, CuActionState.Auditing, null, admittedAt,
            UpdatedAt: admittedAt, PanicEpoch: submitEpoch);
        if (!TryAdmitNonTerminal(auditing, out var admission)) return admission;
        auditing = admission;

        CuVerdict verdict;
        try { verdict = await _auditor.JudgeAsync(action, context, ct).ConfigureAwait(false); }
        catch { verdict = CuVerdict.Hold("broker", "auditor error; held for operator"); }   // fail closed

        var state = verdict.Decision switch
        {
            CuDecision.Allow => CuActionState.Approved,
            CuDecision.Block => CuActionState.Blocked,
            _                => CuActionState.Held,   // Hold (and any unknown) -> operator decides
        };

        // Excursion gate, MODALITY-SCOPED so the browser pin and the desktop one-window gate never cross-fire:
        //  - Browser: pinned-tab excursion (off-tab state changes held; read-only peeks proceed).
        //  - Desktop: one-window excursion (off-window state/cursor-move held; no bound window -> held).
        // Only ever downgrades Allow -> Held; never relaxes a Block/Held.
        if (state == CuActionState.Approved && EvaluateModalityExcursion(action, "for operator") is { } exVerdict)
        {
            verdict = exVerdict;
            if (exVerdict.Decision != CuDecision.Allow) state = CuActionState.Held;
        }

        // Universal Trust is an additional ceiling over the auditor. Ask and unlocked-only-while-locked may only
        // downgrade Allow -> Held; they never relax an auditor Block/Hold.
        if (state == CuActionState.Approved
            && (action.RequiresOperatorApproval || trustDecision?.RequiresApproval == true))
        {
            state = CuActionState.Held;
            verdict = CuVerdict.Hold("trust-policy",
                trustDecision?.Reason ?? "Per-harness policy requires operator approval.");
        }

        // INV-15 (propose-not-act default): a Desktop action from a driver lands HELD for the operator even on an
        // auditor Allow, UNLESS auto-grant is enabled AND still within its bounds (a per-session action budget + an
        // operator-idle gate), so an opted-in auto-grant can never become unbounded standing unattended autonomy. The
        // operator's own actions skip this entirely.
        if (CapabilityGate is null && action.Modality == CuModality.Desktop && state == CuActionState.Approved
            && !string.Equals(action.ByHarness, OperatorMarker, StringComparison.OrdinalIgnoreCase))
        {
            var boundsReason = string.Empty;
            if (DesktopAutoGrant && AutoGrantWithinBounds(out boundsReason))
            {
                Interlocked.Increment(ref _autoGrantUsed);   // count this auto-grant against the per-session budget
            }
            else
            {
                state = CuActionState.Held;
                verdict = CuVerdict.Hold("broker", DesktopAutoGrant
                    ? $"desktop action held: {boundsReason}"
                    : "desktop action held for operator approval (auto-grant off)");
            }
        }

        // Android state changes are propose-not-act: even a local Allow must be explicitly approved by the operator.
        // Observe-only devices/screenshot/ui_dump/logcat can use the audited fast path.
        if (CapabilityGate is null && action.Modality == CuModality.Android && state == CuActionState.Approved
            && CuVerbs.IsStateChanging(action.Verb))
        {
            state = CuActionState.Held;
            verdict = CuVerdict.Hold("broker", "Android state-changing action held for operator approval");
        }

        var item = new CuBrokerItem(id, action, state, verdict, auditing.CreatedAt, UpdatedAt: _utcNow(),
            BoundEpoch: action.Modality == CuModality.Desktop ? _activeWindow?.Epoch : null,
            PanicEpoch: submitEpoch);

        // Panic-during-audit guard (TOCTOU, INV-20): if a panic happened while we were auditing, OnPanicHalt has already
        // Rejected the placeholder and/or bumped the epoch. CAS the audited result in ONLY if the placeholder is still
        // ours; if a panic won the race, respect the terminal Rejected state - NEVER resurrect it.
        lock (_maintenanceLock)
        {
            if (_isHalted() || submitEpoch != Interlocked.Read(ref _panicEpoch))
            {
                var blocked = new CuBrokerItem(id, action, CuActionState.Blocked,
                    CuVerdict.Block("broker", "computer use was halted (panic) during audit"), auditing.CreatedAt,
                    Error: "Halted during audit.", UpdatedAt: _utcNow(), PanicEpoch: submitEpoch);
                _items.TryUpdate(id, blocked, auditing);   // only overwrite if still Auditing; else leave OnPanicHalt's record
                return _items.TryGetValue(id, out var cur) ? cur : blocked;
            }
            if (!_items.TryUpdate(id, item, auditing))
                return _items.TryGetValue(id, out var cur) ? cur : item;   // a concurrent writer won; respect it
        }
        Maintain();
        return item;
    }

    // ── Operator decisions on Held actions ───────────────────────────────────────

    public (bool Ok, string Reason) ApproveHeld(string actionId)
    {
        Maintain();
        lock (_maintenanceLock)
        {
            if (!_items.TryGetValue(actionId, out var item)) return (false, "Unknown action id.");
            if (item.State != CuActionState.Held) return (false, $"Action is {item.State}, not Held.");
            if (_isHalted()) return (false, "Computer use is halted (panic).");
            // OperatorApproved=true so the delivery-time focus re-gate (Claim) won't re-hold this excursion.
            var approved = item with { State = CuActionState.Approved, OperatorApproved = true, UpdatedAt = _utcNow() };
            return _items.TryUpdate(actionId, approved, item)
                ? (true, "Approved.")
                : (false, "Action changed concurrently; approval was not applied.");
        }
    }

    public (bool Ok, string Reason) RejectHeld(string actionId, string? reason = null)
    {
        Maintain();
        lock (_maintenanceLock)
        {
            if (!_items.TryGetValue(actionId, out var item)) return (false, "Unknown action id.");
            if (item.State != CuActionState.Held) return (false, $"Action is {item.State}, not Held.");
            var rejected = item with
            {
                State = CuActionState.Rejected,
                Error = string.IsNullOrWhiteSpace(reason) ? "Rejected by operator." : reason!.Trim(),
                UpdatedAt = _utcNow(),
                ExecutionOwner = null,
                ExecutionToken = null,
            };
            return _items.TryUpdate(actionId, rejected, item)
                ? (true, "Rejected.")
                : (false, "Action changed concurrently; rejection was not applied.");
        }
    }

    // ── Executor: claim Approved actions, then complete them ─────────────────────

    /// <summary>The executor claims up to <paramref name="limit"/> APPROVED actions of exactly one modality, moving
    /// them to Executing and minting an owner-bound, unguessable execution lease. Returns nothing while halted and
    /// re-checks driver authority at delivery. Requiring a modality prevents an executor from accidentally draining a
    /// different surface; requiring an owner prevents a sibling executor from completing or resolving its actions.</summary>
    public IReadOnlyList<CuBrokerItem> Claim(int limit, CuModality modality, string executionOwner)
    {
        Maintain();
        if (_isHalted()) return [];
        var owner = NormalizeExecutionOwner(executionOwner);
        if (owner is null) return [];
        var n = Math.Clamp(limit, 1, 10);
        var batch = new List<CuBrokerItem>(n);
        foreach (var item in _items.Values
                     .Where(i => i.State == CuActionState.Approved && i.Action.Modality == modality)
                     .OrderBy(i => i.CreatedAt))
        {
            if (batch.Count >= n) break;
            if (_isHalted()) break; // a halt between items must not turn the remainder of a batch into Executing
            if (!CanDriveModality(item.Action.ByHarness, isOperator: false, item.Action.Modality))   // INV-14 at delivery
            {
                _items.TryUpdate(item.ActionId, item with
                {
                    State = CuActionState.Rejected,
                    Error = "Driver no longer authorized for this action.",
                    UpdatedAt = _utcNow(),
                    ExecutionOwner = null,
                    ExecutionToken = null,
                }, item);
                continue;
            }

            // Stale across a panic: an item approved before the latest halt is invalidated, never delivered.
            if (item.PanicEpoch < Interlocked.Read(ref _panicEpoch))
            {
                _items.TryUpdate(item.ActionId, item with
                {
                    State = CuActionState.Rejected,
                    Error = "Computer use was halted (panic) after this was approved — re-submit.",
                    UpdatedAt = _utcNow(),
                    ExecutionOwner = null,
                    ExecutionToken = null,
                }, item);
                continue;
            }

            // Re-evaluate universal Trust at DELIVERY. Never revokes even an earlier operator approval; Ask or an
            // unlocked-only policy after Windows locks re-holds unattended work, but a fresh explicit approval wins.
            if (!string.Equals(item.Action.ByHarness, OperatorMarker, StringComparison.OrdinalIgnoreCase)
                && CapabilityGate is { } capabilityGate)
            {
                TrustCapabilityDecision decision;
                try { decision = capabilityGate(item.Action); }
                catch { decision = new TrustCapabilityDecision(true, false, "Universal Trust policy could not be re-evaluated."); }
                if (decision.Blocked)
                {
                    _items.TryUpdate(item.ActionId, item with
                    {
                        State = CuActionState.Rejected,
                        Error = decision.Reason,
                        UpdatedAt = _utcNow(),
                        ExecutionOwner = null,
                        ExecutionToken = null,
                    }, item);
                    continue;
                }
                if (decision.RequiresApproval && !item.OperatorApproved)
                {
                    _items.TryUpdate(item.ActionId, item with
                    {
                        State = CuActionState.Held,
                        Verdict = CuVerdict.Hold("trust-policy", decision.Reason),
                        UpdatedAt = _utcNow(),
                    }, item);
                    continue;
                }
            }

            var deliver = item;
            if (item.Action.Modality == CuModality.Desktop)
            {
                // Desktop one-window confinement re-gate at DELIVERY — NO OperatorApproved skip (spec INV-2): even an
                // operator-approved item re-validates the bound window, so a switch/rebind/recycle since approval is caught.
                if (EvaluateWindowExcursion(item.Action, "at delivery") is { } wv && wv.Decision != CuDecision.Allow)
                {
                    _items.TryUpdate(item.ActionId,
                        item with { State = CuActionState.Held, Verdict = wv, UpdatedAt = _utcNow() }, item);
                    continue;
                }
                var aw = _activeWindow;
                if (item.BoundEpoch is long be && aw is not null && be != aw.Epoch)   // window switched/rebound since approval
                {
                    _items.TryUpdate(item.ActionId, item with { State = CuActionState.Held,
                        Verdict = CuVerdict.Hold("broker", "Bound window switched since approval — re-bind + re-submit."),
                        UpdatedAt = _utcNow() }, item);
                    continue;
                }
                if (aw is not null && WindowProbe is { } probe && !probe.IsAlive(aw))   // recycled-handle / window gone
                {
                    _items.TryUpdate(item.ActionId, item with { State = CuActionState.Held,
                        Verdict = CuVerdict.Hold("broker", "Bound window is no longer alive — re-bind + re-submit."),
                        UpdatedAt = _utcNow() }, item);
                    continue;
                }
                // On-window with no explicit hwnd: STAMP the bound hwnd + epoch so the executor can't pick another window.
                if (aw is not null && (CuVerbs.IsStateChanging(item.Action.Verb) || CuVerbs.IsCursorMoving(item.Action.Verb))
                    && string.IsNullOrEmpty(item.Action.Arg("hwnd")))
                {
                    var stamped = new Dictionary<string, string>(item.Action.Args, StringComparer.Ordinal)
                    {
                        ["hwnd"] = aw.Hwnd.ToInt64().ToString(),
                        ["epoch"] = aw.Epoch.ToString(),
                    };
                    deliver = item with { Action = item.Action with
                        { Args = stamped.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase) } };
                }
            }
            else if (item.Action.Modality == CuModality.Browser)
            {
                // Browser: re-evaluate the pinned-tab gate at delivery (operator-approved excursions pass), then stamp
                // the live pin into a no-tabId state change so the executor cannot divert to the active tab.
                if (!item.OperatorApproved && EvaluateExcursion(item.Action, "at delivery") is { } exV
                    && exV.Decision != CuDecision.Allow)
                {
                    _items.TryUpdate(item.ActionId,
                        item with { State = CuActionState.Held, Verdict = exV, UpdatedAt = _utcNow() }, item);
                    continue;
                }
                if (_attentionTab is { Length: > 0 } pin
                    && CuVerbs.IsStateChanging(item.Action.Verb)
                    && !string.Equals(item.Action.Verb, "navigate", StringComparison.OrdinalIgnoreCase)
                    && string.IsNullOrEmpty(item.Action.Arg("tabId")))
                {
                    var stamped = new Dictionary<string, string>(item.Action.Args, StringComparer.Ordinal) { ["tabId"] = pin };
                    deliver = item with { Action = item.Action with
                        { Args = stamped.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase) } };
                }
            }

            CuBrokerItem? executing = null;
            lock (_maintenanceLock)
            {
                // Serialize the authority check + final Approved -> Executing CAS with panic and modality
                // revocation. Without this lock, panic could snapshot Approved, lose its CAS to this claim, and
                // leave a freshly Executing action alive after the halt epoch had already advanced.
                if (_isHalted() || item.PanicEpoch < Interlocked.Read(ref _panicEpoch))
                    continue;
                // SetDrivers shares this lock. Re-check here, immediately before the transition, so a driver
                // hand-off cannot race the earlier delivery check and mint a fresh execution lease for the old
                // driver after its authority has been removed.
                if (!CanDriveModality(item.Action.ByHarness, isOperator: false, item.Action.Modality))
                {
                    _items.TryUpdate(item.ActionId, item with
                    {
                        State = CuActionState.Rejected,
                        Error = "Driver no longer authorized for this action.",
                        UpdatedAt = _utcNow(),
                        ExecutionOwner = null,
                        ExecutionToken = null,
                    }, item);
                    continue;
                }

                var candidate = deliver with
                {
                    State = CuActionState.Executing,
                    UpdatedAt = _utcNow(),
                    ExecutionOwner = owner,
                    ExecutionToken = NewExecutionToken(),
                };
                if (_items.TryUpdate(item.ActionId, candidate, item))   // CAS against the original Approved item
                    executing = candidate;
            }
            if (executing is not null)
            {
                batch.Add(executing);
                try { OnExecuting?.Invoke(executing); } catch { /* HUD is best-effort; never break delivery */ }
            }
        }
        return batch;
    }

    /// <summary>Validate that an action is still live and the exact executor lease owns it. Vault resolution calls
    /// this both before and after its presence prompt; pumps call it immediately before every physical effect.</summary>
    public (bool Ok, string Reason, CuBrokerItem? Item) ValidateExecution(
        string actionId, CuModality modality, string executionOwner, string executionToken)
    {
        Maintain();
        if (!_items.TryGetValue(actionId, out var item)) return (false, "Unknown action id.", null);
        var reason = ExecutionMismatch(item, modality, executionOwner, executionToken);
        return reason is null ? (true, "Execution lease is valid.", item) : (false, reason, null);
    }

    /// <summary>Only an Executing action may complete, and only with the exact owner/modality/token minted by Claim.
    /// The final transition is CAS so panic, expiry, revocation, and duplicate completions always win safely.</summary>
    public (bool Ok, string Reason) Complete(string actionId, bool ok, object? result, string? error,
        CuModality modality, string executionOwner, string executionToken)
    {
        Maintain();
        lock (_maintenanceLock)
        {
            if (!_items.TryGetValue(actionId, out var item)) return (false, "Unknown action id.");
            if (ExecutionMismatch(item, modality, executionOwner, executionToken) is { } mismatch)
                return (false, mismatch);
            var completed = item with
            {
                State = ok ? CuActionState.Completed : CuActionState.Failed,
                Result = result,
                Error = string.IsNullOrWhiteSpace(error) ? null : error!.Trim(),
                UpdatedAt = _utcNow(),
                ExecutionOwner = null,
                ExecutionToken = null,
            };
            return _items.TryUpdate(actionId, completed, item)
                ? (true, ok ? "Completed." : "Failed.")
                : (false, "Action changed concurrently; completion was not applied.");
        }
    }

    /// <summary>
    /// Reject every non-terminal action for a modality when its live executor authority is revoked or replaced.
    /// Previously-approved work must never survive an Android device/binary re-enrolment and execute later.
    /// </summary>
    public int RevokeModality(CuModality modality, string reason)
    {
        lock (_maintenanceLock)
        {
            var revoked = 0;
            foreach (var pair in _items)
            {
                var item = pair.Value;
                if (item.Action.Modality != modality || item.State is
                    CuActionState.Completed or CuActionState.Failed or CuActionState.Rejected or CuActionState.Blocked)
                    continue;

                var rejected = item with
                {
                    State = CuActionState.Rejected,
                    Error = string.IsNullOrWhiteSpace(reason) ? "Modality authority was revoked." : reason.Trim(),
                    UpdatedAt = _utcNow(),
                    ExecutionOwner = null,
                    ExecutionToken = null,
                };
                if (_items.TryUpdate(pair.Key, rejected, item)) revoked++;
            }
            return revoked;
        }
    }

    // ── Queries ──────────────────────────────────────────────────────────────────

    public CuBrokerItem? Get(string actionId)
    {
        Maintain();
        return _items.TryGetValue(actionId, out var i) ? i : null;
    }

    /// <summary>Current bounded retained record count, primarily for health/limit regression checks.</summary>
    public int ItemCount { get { Maintain(); return _items.Count; } }

    /// <summary>Cheap peek: is there at least one APPROVED action of this modality waiting? Lets the pump gate the HUD
    /// occlusion check + claim only when there is work, so Approved items simply WAIT (not fail) while the HUD is occluded.</summary>
    public bool HasApprovedFor(CuModality modality)
    {
        Maintain();
        return !_isHalted() && _items.Values.Any(i => i.State == CuActionState.Approved && i.Action.Modality == modality);
    }

    public IReadOnlyList<CuBrokerItem> ListHeld()
    {
        Maintain();
        return _items.Values.Where(i => i.State == CuActionState.Held).OrderBy(i => i.CreatedAt).ToList();
    }

    // ── Driver gating (ported from LiveWeaveBroker) ──────────────────────────────

    /// <summary>The authorized driver set, normalized: empty = operator-only, ["*"] = any harness, else harness ids.</summary>
    // Never expose the live authority array: IReadOnlyList is only a compile-time view and a caller could cast a
    // returned string[] back to IList<string> and mutate the broker's driver set without SetDrivers/revocation.
    public IReadOnlyList<string> Drivers => _drivers.ToArray();

    /// <summary>Back-compat single-string view: null = operator-only, "*" = any, else the ids joined by commas.</summary>
    public string? Driver => _drivers.Length == 0 ? null : string.Join(",", _drivers);

    /// <summary>Optional sink invoked whenever the driver set changes, so the host can persist it across restarts.
    /// Receives the NORMALIZED <see cref="Driver"/> string ("*" = any, null = operator-only, else comma-joined ids).
    /// Wire it AFTER the startup seed (call <see cref="SetDriver"/> with the saved value first) so restoring doesn't re-save.</summary>
    public Action<string?>? DriverPersister { get; set; }

    /// <summary>Back-compat single setter: accepts one id, "any", blank (operator-only), OR a comma-separated list
    /// (so a persisted "a,b" round-trips). Delegates to <see cref="SetDrivers"/>.</summary>
    public (bool Ok, string Reason) SetDriver(string? harnessId) =>
        SetDrivers(string.IsNullOrWhiteSpace(harnessId)
            ? null
            : harnessId.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    /// <summary>Sets the full authorized driver set. Each id is normalized (trim/lower-case, "any" -> "*"); if "*"
    /// is present it supersedes the specifics and collapses to ["*"] (any harness). Empty -> operator-only.</summary>
    public (bool Ok, string Reason) SetDrivers(IEnumerable<string>? harnessIds)
    {
        var set = (harnessIds ?? [])
            .Select(h => (h ?? string.Empty).Trim().ToLowerInvariant())
            .Where(h => h.Length > 0)
            .Select(h => string.Equals(h, "any", StringComparison.OrdinalIgnoreCase) ? "*" : h)
            .Distinct()
            .ToArray();
        lock (_maintenanceLock)
        {
            var next = set.Contains("*") ? ["*"] : set;
            if (_drivers.SequenceEqual(next, StringComparer.Ordinal))
                return (true, "Driver authority was unchanged.");

            // Persistence/sealing is part of the authority transaction. Granting live driver power first and then
            // discovering that a Guardian-backed save was refused creates an undocumented session-only bypass.
            // Serialize this with claim/revocation and apply the live set only after persistence succeeds.
            var persisted = next.Length == 0 ? null : string.Join(",", next);
            if (DriverPersister is { } persist)
            {
                try { persist(persisted); }
                catch (Exception ex)
                {
                    return (false, $"Driver authority was not changed because persistence failed ({ex.GetType().Name}).");
                }
            }

            _drivers = next;

            // Driver selection is live authority, not merely an admission preference. Revoke queued AND already
            // executing browser/Android work whose submitting harness is no longer selected. Actions belonging to
            // retained drivers survive, which preserves intentional multi-harness and seamless hand-off workflows.
            foreach (var pair in _items)
            {
                var item = pair.Value;
                if (item.State is CuActionState.Completed or CuActionState.Failed
                    or CuActionState.Rejected or CuActionState.Blocked)
                    continue;
                if (CanDriveModality(item.Action.ByHarness, isOperator: false, item.Action.Modality))
                    continue;

                _items.TryUpdate(pair.Key, item with
                {
                    State = CuActionState.Rejected,
                    Error = "Driver authority was removed before the action completed.",
                    UpdatedAt = _utcNow(),
                    ExecutionOwner = null,
                    ExecutionToken = null,
                }, item);
            }
        }
        return (true, "Driver authority updated.");
    }

    // Derived DESKTOP driver enrollments, kept SEPARATE from the persisted browser driver set (_drivers). Desktop
    // authority reads from here too, so an operator browser-driver change (SetDrivers via cu_set_driver / the picker)
    // can NEVER silently drop it, and it is never persisted (re-applied each startup from the sealed CuDriverHostEnabled
    // flag, so a settings edit alone can't enroll it).
    private readonly object _enrollLock = new();
    private readonly HashSet<string> _desktopEnrollments = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _androidEnrollments = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Enroll an explicit DESKTOP driver id (e.g. "local-agent-host"). Stored in a derived set separate from
    /// the persisted browser driver set, so a later browser-driver change cannot drop it and it is never persisted. The
    /// App re-applies it each startup from the sealed + presence-armed CuDriverHostEnabled flag, so a settings edit alone
    /// can't enroll it. INV-14: a desktop driver must be an explicit id; "*" is rejected here.</summary>
    public void EnrollDesktopDriver(string id)
    {
        var norm = (id ?? string.Empty).Trim().ToLowerInvariant();
        if (norm.Length == 0 || norm == "*") return;
        lock (_enrollLock) _desktopEnrollments.Add(norm);
    }

    /// <summary>
    /// Replaces the explicit Android device enrolment set. Device identity is separate from harness authority: a
    /// harness must be in <see cref="Drivers"/> AND its requested serial must be enrolled. The App seeds this from
    /// the presence-gated, sealed ADB settings at startup.
    /// </summary>
    public void SetAndroidDevices(IEnumerable<string>? serials)
    {
        var normalized = (serials ?? [])
            .Select(static s => (s ?? string.Empty).Trim())
            .Where(AdbBridgeExecutor.IsSafeSerial)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        lock (_enrollLock)
        {
            _androidEnrollments.Clear();
            foreach (var serial in normalized)
                _androidEnrollments.Add(serial);
        }
    }

    public IReadOnlyList<string> AndroidDevices
    {
        get
        {
            lock (_enrollLock)
                return _androidEnrollments.Order(StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }

    public bool CanDrive(string? harnessId, bool isOperator)
    {
        if (isOperator || string.Equals(harnessId, OperatorMarker, StringComparison.OrdinalIgnoreCase)) return true;
        var d = _drivers;
        if (d.Length == 0) return false;
        if (d.Contains("*")) return true;
        return harnessId is not null && d.Contains(harnessId.Trim().ToLowerInvariant());
    }

    /// <summary>Modality-aware driver gate (spec INV-14): the "*" wildcard NEVER authorizes the Desktop modality - a
    /// desktop driver must be an EXPLICITLY enumerated, operator-enrolled id (e.g. "local-agent-host"). The operator /
    /// Hello root always passes. Browser and Android use the operator's shared driver set.</summary>
    public bool CanDriveModality(string? harnessId, bool isOperator, CuModality modality)
    {
        if (isOperator || string.Equals(harnessId, OperatorMarker, StringComparison.OrdinalIgnoreCase)) return true;
        var id = harnessId?.Trim().ToLowerInvariant();
        if (id is null) return false;
        var d = _drivers;
        if (modality == CuModality.Desktop)
        {
            // Desktop authority = an EXPLICITLY enrolled id, NEVER "*": from the derived enrollment set (survives a
            // browser-driver change; never persisted) OR an explicit operator-set driver id.
            lock (_enrollLock) { if (_desktopEnrollments.Contains(id)) return true; }
            return d.Contains(id);
        }
        if (d.Length == 0) return false;
        if (d.Contains("*")) return true;
        return d.Contains(id);
    }

    /// <summary>Opt-in: let a desktop action that audits to Allow proceed without operator approval. Default OFF, so a
    /// desktop action from a driver is always Held for the operator (INV-15). The App wires this from settings. Even when
    /// ON it is BOUNDED by <see cref="AutoGrantMaxActions"/> + the <see cref="OperatorIdle"/> gate.</summary>
    public bool DesktopAutoGrant { get; set; }

    private int _autoGrantUsed;

    /// <summary>Per-session cap on auto-granted desktop actions before falling back to Held - so an opted-in auto-grant
    /// can't become unbounded unattended autonomy (INV-15). Default 50; &lt;= 0 disables the count cap.</summary>
    public int AutoGrantMaxActions { get; set; } = 50;

    /// <summary>App-wired probe of how long the operator has been idle (no keyboard/mouse). Null = no idle gate. When set,
    /// auto-grant pauses (actions fall back to Held) once idle exceeds <see cref="AutoGrantIdleRevoke"/>, so an agent
    /// can't run unattended while the operator is away from the machine.</summary>
    public Func<TimeSpan>? OperatorIdle { get; set; }
    public TimeSpan AutoGrantIdleRevoke { get; set; } = TimeSpan.FromSeconds(60);

    private bool AutoGrantWithinBounds(out string reason)
    {
        reason = string.Empty;
        if (AutoGrantMaxActions > 0 && Volatile.Read(ref _autoGrantUsed) >= AutoGrantMaxActions)
        { reason = $"auto-grant budget exhausted ({AutoGrantMaxActions} actions) - re-confirm to continue"; return false; }
        if (OperatorIdle is { } idle && idle() > AutoGrantIdleRevoke)
        { reason = "operator idle - auto-grant paused until you return"; return false; }
        return true;
    }

    // ── Pinned shared-attention (focus-lock) ─────────────────────────────────────

    /// <summary>The operator's pinned shared-attention tab (the locked focus), or null when nothing is pinned.</summary>
    public string? AttentionTab => _attentionTab;

    /// <summary>Sets the pinned attention tab (the executor reports the operator's pinned-icon choice). Blank clears it.</summary>
    public void SetAttention(string? tabId) => _attentionTab = string.IsNullOrWhiteSpace(tabId) ? null : tabId.Trim();

    // True when a pin is set AND the action leaves it: either an explicit args["tabId"] != pin, or a 'navigate'
    // (which opens a NEW tab, always off the pinned focus). No pin set -> never an excursion. No explicit tabId on a
    // tab-acting verb -> the executor runs it IN the pinned tab, so that is on-focus, not an excursion.
    private bool IsOffPinExcursion(CuAction action, out string? target, out string? justification)
    {
        justification = action.Arg("justification") is { Length: > 0 } j ? j : null;
        target = action.Arg("tabId") is { Length: > 0 } t ? t : null;
        if (string.IsNullOrEmpty(_attentionTab)) return false;
        // 'navigate' opens a NEW tab, which always leaves the pinned focus.
        if (string.Equals(action.Verb?.Trim(), "navigate", StringComparison.OrdinalIgnoreCase)) { target ??= "a new tab"; return true; }
        if (string.IsNullOrEmpty(target)) return false;   // no explicit tab -> runs in the pinned tab (stamped at delivery)
        return !TabsMatch(target, _attentionTab);
    }

    // Canonical integer compare for tab ids: parse both sides so "042"/" 42 " match "42", and a NON-integer tabId
    // (which the executor resolves differently, or rejects) is treated as off-focus (conservative). The verb
    // classifier is the shared CuVerbs.IsStateChanging so the pin gate and the audit pipeline never diverge.
    private static bool TabsMatch(string? a, string? b) =>
        long.TryParse(a, out var ai) && long.TryParse(b, out var bi) && ai == bi;

    private CuVerdict ExcursionHold(string? target, string? justification, string when) =>
        CuVerdict.Hold("broker",
            $"Off-focus change held {when} (pinned tab {_attentionTab}; action targets {target})" +
            (string.IsNullOrWhiteSpace(justification) ? " — no justification given." : $": {justification}"));

    /// <summary>Operator opt-in (from settings.CuTabOverride): when true, an off-focus state change may PROCEED
    /// instead of being held — but ONLY if it carries a justification. Default false (off-focus changes are held).</summary>
    public bool AllowTabOverride { get; set; }

    /// <summary>Fired when an action is handed to the executor (moves to Executing). The App raises the operator
    /// HUD overlay ("CLAUDE DRIVING THRU TRACEBRAKE") from it. Invoked on the poll thread — marshal to the UI thread.</summary>
    public Action<CuBrokerItem>? OnExecuting { get; set; }

    // The off-focus verdict for a state-changing action, or null when there is no excursion (on-focus / read-only /
    // no pin). With tab-override opted in AND a justification present -> Allow (proceeds, surfaced); otherwise Hold.
    // A justification is mandatory to ever proceed off-focus, so the implicit-auth assumption is always explained.
    private CuVerdict? EvaluateExcursion(CuAction action, string when)
    {
        if (!CuVerbs.IsStateChanging(action.Verb)) return null;
        if (!IsOffPinExcursion(action, out var target, out var just)) return null;
        if (AllowTabOverride && !string.IsNullOrWhiteSpace(just))
            return CuVerdict.Allow("broker", $"Off-focus override (operator opt-in) {when} (targets {target}): {just}");
        return ExcursionHold(target, just, AllowTabOverride ? $"{when} — override needs a justification" : when);
    }

    // Modality-scoped dispatch: browser actions hit the pinned-tab gate, desktop actions the one-window gate.
    private CuVerdict? EvaluateModalityExcursion(CuAction a, string when) =>
        a.Modality switch
        {
            CuModality.Desktop => EvaluateWindowExcursion(a, when),
            CuModality.Browser => EvaluateExcursion(a, when),
            _ => null,
        };

    // ── Desktop one-window confinement (parallel to the pin; modality-scoped) ────

    /// <summary>The operator-bound active CU window (desktop), or null. Switching is explicit and Epoch-bumped.</summary>
    public CuWindowRef? ActiveWindow => _activeWindow;

    /// <summary>App-supplied probe for liveness checks at delivery (recycled-handle defense); null in tests/headless.</summary>
    public IDesktopWindowProbe? WindowProbe { get; set; }

    /// <summary>App-wired one-time bind-token validator (spec INV-17). When set, a desktop BIND must present a token
    /// the validator accepts - one the presence gate minted on a real operator BindCuWindow tap and consumes once - so
    /// a caller cannot fabricate a CuWindowRef for an attacker-owned window and bind it. Null in tests/headless means
    /// no token is required (the App wires this when the local agent host is enabled).</summary>
    public Func<string?, bool>? BindTokenValidator { get; set; }

    /// <summary>Fired when the bound CU window changes (old, new) — the App announces it via the HUD + audit log.</summary>
    public Action<CuWindowRef?, CuWindowRef?>? OnWindowSwitch { get; set; }

    /// <summary>Fired when desktop cursor ownership changes (for the Shared-Monopilot cursor in a later slice).</summary>
    public Action<CuBrokerItem, bool>? OnHandoff { get; set; }

    /// <summary>Binds (or clears, with null) the single active CU window. REFUSES TraceBrake's own windows. Bumps the
    /// Epoch so any action approved against a prior binding is re-held at delivery. The caller presence-gates the bind.</summary>
    public (bool Ok, string Reason) SetActiveWindow(CuWindowRef? w, string? bindToken = null)
    {
        if (w is not null)
        {
            if (w.OwnerPid == Environment.ProcessId)
                return (false, "Refused: cannot bind TraceBrake's own window as a CU target.");
            // INV-17: a bind must carry a live one-time token the presence gate minted on a real operator tap, so a
            // caller cannot hand the broker a fabricated CuWindowRef for a window the operator never chose.
            if (BindTokenValidator is { } validate && !validate(bindToken))
                return (false, "Refused: bind not authorized by a live presence tap (missing/invalid bind token).");
        }
        var old = _activeWindow;
        _activeWindow = w is null ? null : w with { Epoch = Interlocked.Increment(ref _windowEpoch) };
        try { OnWindowSwitch?.Invoke(old, _activeWindow); } catch { /* best-effort announce */ }
        return (true, w is null ? "Cleared the bound CU window." : $"Bound CU window '{w.TitleAtBind}' (pid {w.OwnerPid}).");
    }

    /// <summary>Called on a panic HALT: invalidate every modality, including already-claimed Browser work. The
    /// execution lease is erased, so a stale extension/pump cannot resolve a vault reference or report success after
    /// the stop. Executors must still re-check the action immediately before each physical effect.</summary>
    public void OnPanicHalt()
    {
        lock (_maintenanceLock)
        {
            Interlocked.Increment(ref _panicEpoch);
            foreach (var item in _items.Values)
            {
                if (item.State is CuActionState.Auditing or CuActionState.Held or CuActionState.Approved or CuActionState.Executing)
                    _items.TryUpdate(item.ActionId, item with
                    {
                        State = CuActionState.Rejected,
                        Error = "Computer use was halted (panic) — re-submit.",
                        OperatorApproved = false,
                        UpdatedAt = _utcNow(),
                        ExecutionOwner = null,
                        ExecutionToken = null,
                    }, item);
            }
        }
    }

    // Desktop one-window gate. Gated verbs = state-changing OR cursor-moving (a move/scroll leaves confinement too).
    // No window bound -> a gated verb is Held. Bound + the action targets a DIFFERENT hwnd -> Held (off-window). On
    // the bound window (matching hwnd, or no explicit hwnd -> runs in it) -> null (proceeds; hwnd stamped at delivery).
    private CuVerdict? EvaluateWindowExcursion(CuAction action, string when)
    {
        if (!CuVerbs.IsStateChanging(action.Verb) && !CuVerbs.IsCursorMoving(action.Verb)) return null;
        var just = action.Arg("justification") is { Length: > 0 } j ? j : null;
        var target = action.Arg("hwnd") is { Length: > 0 } t ? t : null;
        var aw = _activeWindow;
        if (aw is null)
            return CuVerdict.Hold("broker", $"Desktop action held {when}: no CU window is bound — the operator must bind a target window first.");
        if (!string.IsNullOrEmpty(target) && !HwndMatches(target, aw.Hwnd))
            return CuVerdict.Hold("broker",
                $"Off-window change held {when} (bound HWND {aw.Hwnd} '{aw.TitleAtBind}'; action targets {target})" +
                (string.IsNullOrWhiteSpace(just) ? "." : $": {just}"));
        return null;
    }

    private static bool HwndMatches(string? a, IntPtr b) => long.TryParse(a, out var ai) && ai == b.ToInt64();

    // Token-bucket rate limit per harness: refill RatePerSecond up to RateBurst; consume 1 per submit. Empty -> false
    // (the submit is Held). Locked because submit is not a hot path and correctness beats lock-free here.
    private bool RateLimitOk(string harness)
    {
        lock (_rateLock)
        {
            var now = _utcNow().Ticks;
            if (!_rate.ContainsKey(harness) && _rate.Count >= 256)
            {
                foreach (var stale in _rate.OrderBy(kv => kv.Value.Ticks).Take(_rate.Count - 255).Select(kv => kv.Key).ToArray())
                    _rate.Remove(stale);
            }
            if (!_rate.TryGetValue(harness, out var cur)) { _rate[harness] = (RateBurst - 1, now); return true; }
            var elapsedSec = (now - cur.Ticks) / (double)TimeSpan.TicksPerSecond;
            var tokens = Math.Min(RateBurst, cur.Tokens + elapsedSec * RatePerSecond);
            if (tokens >= 1) { _rate[harness] = (tokens - 1, now); return true; }
            _rate[harness] = (tokens, now);
            return false;
        }
    }

    private static string NewActionId() => Guid.NewGuid().ToString("N")[..12];

    private static string NewExecutionToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    private static bool IsValidActionId(string id) =>
        id.Length is >= 1 and <= 64 && id.All(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z'
            or >= '0' and <= '9' or '_' or '-');

    private static CuAction BoundedRejectionAction(CuAction action, string id) => new(
        Enum.IsDefined(action.Modality) ? action.Modality : CuModality.Browser,
        (action.Verb ?? string.Empty).Length <= 40 ? action.Verb ?? string.Empty : (action.Verb ?? string.Empty)[..40],
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase).ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
        ByHarness: string.IsNullOrWhiteSpace(action.ByHarness) ? null : action.ByHarness.Trim()[..Math.Min(action.ByHarness.Trim().Length, 128)],
        ActionId: id,
        SessionId: string.IsNullOrWhiteSpace(action.SessionId) ? null : action.SessionId.Trim()[..Math.Min(action.SessionId.Trim().Length, 128)],
        Isolation: Enum.IsDefined(action.Isolation) ? action.Isolation : CuIsolationMode.SharedMonopilot,
        RequiresOperatorApproval: action.RequiresOperatorApproval);

    private static bool TrySnapshotAction(CuAction source, string id, out CuAction snapshot, out string reason)
    {
        snapshot = BoundedRejectionAction(source, id);
        reason = string.Empty;
        if (!Enum.IsDefined(source.Modality)) { reason = "Unknown computer-use modality."; return false; }
        if (!Enum.IsDefined(source.Isolation)) { reason = "Unknown computer-use isolation mode."; return false; }
        if (source.Args is null) { reason = "Action arguments are required."; return false; }
        if (source.Args.Count > 32) { reason = "Action may contain at most 32 arguments."; return false; }
        if ((source.ByHarness?.Length ?? 0) > 128 || (source.SessionId?.Length ?? 0) > 128)
        { reason = "Harness/session identity is too long."; return false; }

        var args = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var totalChars = 0;
        foreach (var pair in source.Args)
        {
            var key = pair.Key?.Trim() ?? string.Empty;
            var value = pair.Value ?? string.Empty;
            if (key.Length is < 1 or > 64) { reason = "Action argument names must be 1-64 characters."; return false; }
            if (value.Length > 16 * 1024) { reason = $"Action argument '{key}' exceeds the 16 KiB cap."; return false; }
            totalChars += key.Length + value.Length;
            if (totalChars > 64 * 1024) { reason = "Action arguments exceed the 64 KiB aggregate cap."; return false; }
            if (!args.TryAdd(key, value)) { reason = $"Duplicate action argument '{key}'."; return false; }
        }

        snapshot = source with
        {
            Verb = (source.Verb ?? string.Empty).Trim(),
            Args = args.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
            ByHarness = string.IsNullOrWhiteSpace(source.ByHarness) ? null : source.ByHarness.Trim(),
            ActionId = id,
            SessionId = string.IsNullOrWhiteSpace(source.SessionId) ? null : source.SessionId.Trim(),
        };
        return true;
    }

    private CuBrokerItem BlockAndRecord(string id, CuAction action, string verdictReason, string error)
    {
        if (!TrySnapshotAction(action, id, out var safe, out _)) safe = BoundedRejectionAction(action, id);
        var now = _utcNow();
        return StoreTerminal(new CuBrokerItem(id, safe, CuActionState.Blocked,
            CuVerdict.Block("broker", verdictReason), now, Error: error, UpdatedAt: now));
    }

    private static bool IsNonTerminal(CuActionState state) => state is
        CuActionState.Auditing or CuActionState.Held or CuActionState.Approved or CuActionState.Executing;

    private static string HarnessBucket(CuAction action) =>
        string.IsNullOrWhiteSpace(action.ByHarness) ? "operator" : action.ByHarness.Trim().ToLowerInvariant();

    private bool TryAdmitNonTerminal(CuBrokerItem requested, out CuBrokerItem admitted)
    {
        lock (_maintenanceLock)
        {
            ExpireStaleUnsafe();
            PruneTerminalUnsafe(_options.MaxItems - 1);
            if (_isHalted())
            {
                admitted = StoreTerminalUnsafe(CapacityBlock(requested,
                    "Computer use is halted (panic); non-terminal work was not admitted."));
                return false;
            }
            if (_items.ContainsKey(requested.ActionId))
            {
                admitted = StoreTerminalUnsafe(CapacityBlock(requested, "Duplicate action id; existing action was not overwritten."));
                return false;
            }

            var pending = _items.Values.Where(i => IsNonTerminal(i.State)).ToArray();
            if (pending.Length >= _options.MaxNonTerminalItems)
            {
                admitted = StoreTerminalUnsafe(CapacityBlock(requested,
                    $"Computer-use pending queue is full (cap {_options.MaxNonTerminalItems})."));
                return false;
            }
            var bucket = HarnessBucket(requested.Action);
            if (pending.Count(i => string.Equals(HarnessBucket(i.Action), bucket, StringComparison.Ordinal))
                >= _options.MaxNonTerminalPerHarness)
            {
                admitted = StoreTerminalUnsafe(CapacityBlock(requested,
                    $"Computer-use pending queue for this harness is full (cap {_options.MaxNonTerminalPerHarness})."));
                return false;
            }
            if (_items.Count >= _options.MaxItems)
            {
                admitted = CapacityBlock(requested, "Computer-use record capacity is full.");
                return false; // all retained records are live; never exceed the hard bound merely to record refusal
            }
            if (_items.TryAdd(requested.ActionId, requested))
            {
                admitted = requested;
                return true;
            }
            admitted = StoreTerminalUnsafe(CapacityBlock(requested, "Duplicate action id; existing action was not overwritten."));
            return false;
        }
    }

    private CuBrokerItem CapacityBlock(CuBrokerItem requested, string reason)
    {
        var id = requested.ActionId;
        if (_items.ContainsKey(id)) id = NewActionId();
        var now = _utcNow();
        return requested with
        {
            ActionId = id,
            Action = requested.Action with { ActionId = id },
            State = CuActionState.Blocked,
            Verdict = CuVerdict.Block("broker-capacity", reason),
            Error = reason,
            UpdatedAt = now,
            OperatorApproved = false,
            ExecutionOwner = null,
            ExecutionToken = null,
        };
    }

    private CuBrokerItem StoreTerminal(CuBrokerItem item)
    {
        lock (_maintenanceLock)
        {
            ExpireStaleUnsafe();
            return StoreTerminalUnsafe(item);
        }
    }

    private CuBrokerItem StoreTerminalUnsafe(CuBrokerItem item)
    {
        PruneTerminalUnsafe(_options.MaxItems - 1);
        if (_items.ContainsKey(item.ActionId)) item = CapacityBlock(item, "Duplicate action id; existing action was not overwritten.");
        if (_items.Count < _options.MaxItems) _items.TryAdd(item.ActionId, item);
        return item;
    }

    private void Maintain()
    {
        lock (_maintenanceLock)
        {
            ExpireStaleUnsafe();
            PruneTerminalUnsafe(_options.MaxItems);
        }
    }

    private void ExpireStaleUnsafe()
    {
        var now = _utcNow();
        foreach (var pair in _items)
        {
            var item = pair.Value;
            var ttl = item.State switch
            {
                CuActionState.Auditing => _options.AuditingTtl,
                CuActionState.Held => _options.HeldTtl,
                CuActionState.Approved => _options.ApprovedTtl,
                CuActionState.Executing => _options.ExecutingTtl,
                _ => TimeSpan.Zero,
            };
            if (ttl == TimeSpan.Zero || now - (item.UpdatedAt ?? item.CreatedAt) <= ttl) continue;
            _items.TryUpdate(pair.Key, item with
            {
                State = CuActionState.Rejected,
                Error = $"Computer-use action expired while {item.State}; re-submit.",
                UpdatedAt = now,
                OperatorApproved = false,
                ExecutionOwner = null,
                ExecutionToken = null,
            }, item);
        }
    }

    private void PruneTerminalUnsafe(int targetCount)
    {
        if (_items.Count <= targetCount) return;
        foreach (var id in _items.Values
                     .Where(i => !IsNonTerminal(i.State))
                     .OrderBy(i => i.UpdatedAt ?? i.CreatedAt)
                     .Take(_items.Count - targetCount)
                     .Select(i => i.ActionId)
                     .ToArray())
            _items.TryRemove(id, out _);
    }

    private static string? NormalizeExecutionOwner(string? executionOwner)
    {
        var owner = executionOwner?.Trim();
        return owner is { Length: >= 1 and <= 128 } && owner.All(c => !char.IsControl(c))
            ? owner.ToLowerInvariant()
            : null;
    }

    private string? ExecutionMismatch(CuBrokerItem item, CuModality modality,
        string executionOwner, string executionToken)
    {
        if (_isHalted()) return "Computer use is halted (panic).";
        if (item.State != CuActionState.Executing) return $"Action is {item.State}, not Executing.";
        if (item.Action.Modality != modality) return "Executor modality does not own this action.";
        var owner = NormalizeExecutionOwner(executionOwner);
        if (owner is null || !string.Equals(item.ExecutionOwner, owner, StringComparison.Ordinal))
            return "Executor identity does not own this action.";
        if (!ExecutionTokensMatch(item.ExecutionToken, executionToken))
            return "Execution lease is invalid.";
        return null;
    }

    private static bool ExecutionTokensMatch(string? actual, string? supplied)
    {
        if (actual is not { Length: 64 } || supplied is not { Length: 64 }) return false;
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), Convert.FromHexString(supplied));
        }
        catch (FormatException) { return false; }
    }
}
