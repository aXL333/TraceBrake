namespace Foreman.Core.Settings;

public sealed class ForemanSettings
{
    public int McpPort { get; set; } = 54321;

    /// <summary>
    /// Whole-process no-I/O minutes before a harness child counts as hung. 30 by default — AI agents
    /// legitimately go I/O-quiet for long stretches (thinking, long builds); 10 proved too chatty in
    /// the field. Hooks use the tighter <see cref="HookJamThresholdMinutes"/>.
    /// </summary>
    public int HangThresholdMinutes { get; set; } = 30;
    public int HookJamThresholdMinutes { get; set; } = 5;

    /// <summary>
    /// After a hang alert for a process, suppress further hang alerts for that same PID for this many
    /// minutes — even if its I/O briefly resumes and it idles again. Stops a bursty-I/O child (language
    /// server, file watcher, MCP helper) from re-firing a "no I/O" alert on every idle stretch. 0 = no
    /// cooldown (re-arm immediately on each new silent episode).
    /// </summary>
    public int HangRealertCooldownMinutes { get; set; } = 60;

    /// <summary>
    /// Operator-set notification mutes (see <see cref="Foreman.Core.Models.MutePolicy"/>). These only
    /// quiet tray popups — detection, logging, dashboard counts and escalation are unaffected.
    /// </summary>
    public List<Foreman.Core.Models.MuteEntry> Mutes { get; set; } = [];
    public int IoPollerIntervalSeconds { get; set; } = 30;
    public bool NotifyOnHang { get; set; } = true;
    public bool NotifyOnOrphan { get; set; } = true;
    public bool NotifyOnCriticalCommand { get; set; } = true;
    public bool NotifyOnWarning { get; set; } = true;       // medium-severity "warning" toasts; false = mute the yellow popups (still logged + shown)
    public bool MonitorAllProcesses { get; set; } = false; // false = harness children only

    /// <summary>Persisted mediated browser/Android (cu_*) driver set: which harnesses may drive. Normalized form:
    /// null/empty = operator-only, "*" = any harness, else a harness id. Restored into the CuBroker on startup
    /// so the operator doesn't have to re-pick it after every relaunch.</summary>
    public string? CuDriver { get; set; }

    /// <summary>Opt-in: let the browser-use driver act in a tab OTHER than the pinned focus WITHOUT waiting for
    /// operator approval — but only when the action carries a justification (the implicit-auth assumption is always
    /// explained + logged). Off by default: off-focus state changes are HELD for the operator. A justification is
    /// mandatory to ever proceed off-focus, opt-in or not.</summary>
    public bool CuTabOverride { get; set; }

    /// <summary>Opt-in: enable the medium-IL desktop computer-use sidecar (SendInput + screen capture, confined to
    /// one bound window). OFF by default and deliberately separate from browser CU - desktop input is operator-driven
    /// in-process only, never offered over MCP (spec INV-7). When set, the App launches and handshakes the sidecar.</summary>
    public bool CuDesktopEnabled { get; set; }

    /// <summary>Opt-in: enable the Local Agent Host - TraceBrake launches a signed Pilot shim so a LOCAL AI agent can
    /// pilot the desktop through the audited path (spec L3+; never the network, never MCP). OFF by default; arming
    /// additionally requires an enrolled presence credential (INV-16). When set, the App launches + handshakes the
    /// pilot shim.</summary>
    public bool CuDriverHostEnabled { get; set; }

    /// <summary>The local AI agent TraceBrake launches for the agent host (HOP B): the executable/command, its arguments,
    /// and working dir. OPERATOR config only - never agent-supplied. Empty Command = run HOP A only (no agent). The
    /// shim hands the launched agent the HOP B pipe name + session secret via its stdin (an inherited handle).</summary>
    public string? CuAgentCommand { get; set; }
    public string? CuAgentArguments { get; set; }
    public string? CuAgentWorkingDir { get; set; }

    /// <summary>Opt-in: let a desktop action that audits to Allow proceed WITHOUT operator approval. OFF by default
    /// (INV-15 propose-not-act) - every desktop action from a driver is Held for the operator. Sealed (a settings edit
    /// flipping this on is tamper-detected). Leave off unless you accept unattended desktop autonomy.</summary>
    public bool CuDesktopAutoGrant { get; set; }

    /// <summary>
    /// Opt-in Android Debug Bridge modality. It is deliberately a bounded broker, not raw adb access: only enrolled
    /// device serials and TraceBrake's fixed devices/screenshot/UI-dump/logcat/install/tap/type/swipe/key verbs are available.
    /// Harness authority still comes from <see cref="CuDriver"/> plus the per-harness computer-use policy.
    /// </summary>
    public AdbBridgeSettings AdbBridge { get; set; } = new();

    /// <summary>Persist the event log to disk (JSONL) so it survives restarts. On by default.</summary>
    public bool EventLogPersist { get; set; } = true;

    /// <summary>
    /// Tamper-evidence for the on-disk event log: an append-only hash chain (P1) + a TPM-sealed head (P3).
    /// See <see cref="LogIntegritySettings"/>. The audit log is the record a rogue agent would most want to
    /// rewrite to hide its tracks, so this makes edits/drops/reorders detectable.
    /// </summary>
    public LogIntegritySettings LogIntegrity { get; set; } = new();

    /// <summary>
    /// Opt-in: launch an elevated, capture-only ETW sidecar so the Process Monitor can show
    /// per-process Network throughput. Off by default — only the sidecar runs elevated; the main
    /// app (UI, MCP server, kill action) stays at medium integrity. Toggling it on prompts UAC.
    /// </summary>
    public bool RunElevated { get; set; } = false;

    /// <summary>
    /// Opt-in (Tier 1): periodically connect to the HTTP/SSE MCP servers your harnesses use,
    /// enumerate their tools, and scan the tool names + descriptions for prompt-injection / data-
    /// exfil text. Off by default — this is the only feature that makes outbound network connections
    /// to third-party servers. stdio servers are never launched (we don't spawn what we're auditing).
    /// </summary>
    public bool ScanMcpTools { get; set; } = false;

    /// <summary>
    /// Origins of paired TraceBrake browser extensions (e.g. "chrome-extension://&lt;id&gt;") allowed to reach the
    /// MCP endpoint in addition to loopback. Empty by default — populated by the extension pairing flow.
    /// Consumed by <see cref="Foreman.Core.Mcp.LoopbackRequestPolicy"/>. (Closed-loop spec.)
    /// </summary>
    public List<string> PairedExtensionOrigins { get; set; } = [];

    /// <summary>
    /// When true, a first-party browser extension may auto-pair over loopback DURING an operator-armed pairing
    /// window without the on-screen code — the operator's act of clicking "Pair browser extension" is the consent,
    /// and the extension receives only a SCOPED token. Strictly weaker than the code path (ANY loopback extension
    /// origin can grab a scoped token within that short window — it is not bound to a specific extension id), so each
    /// auto-pair is announced as a Medium notice. Default OFF: the on-screen HMAC code is required for every extension
    /// pair, matching this path's "explicit opt-in only" intent; flip on to allow code-less one-click linking.
    /// </summary>
    public bool AllowAutoExtensionPairing { get; set; }

    // ── Idle Harness self-cleanup ────────────────────────────────────────────

    /// <summary>
    /// Opt-in: when a harness's whole process tree has been I/O-silent past the threshold,
    /// automatically ask it over MCP to pack up cleanly (checkpoint work, stop leftover
    /// children, reply or exit). The manual per-harness trigger in the Process Monitor works
    /// regardless of this setting.
    /// </summary>
    public bool IdleCleanupEnabled { get; set; } = false;

    /// <summary>Minutes of whole-tree I/O silence before a harness counts as idle.</summary>
    public int IdleCleanupAfterMinutes { get; set; } = 45;

    /// <summary>Minutes to wait for a reply before surfacing an "unanswered cleanup request" notice.</summary>
    public int IdleCleanupGraceMinutes { get; set; } = 15;

    /// <summary>Per-harness cooldown between automatic cleanup requests, so TraceBrake never nags.</summary>
    public int IdleCleanupCooldownMinutes { get; set; } = 120;

    public string ProfilesDirectory { get; set; } =
        Path.Combine(ProductIdentity.LocalDataRoot, "profiles");

    /// <summary>
    /// Harness IDs (matching KnownHarnesses.All[].Id, or "custom:exename.exe") that
    /// should not be monitored.  TraceBrake still detects them for status display purposes
    /// but will not emit hang/orphan/permission alerts for disabled harnesses.
    /// </summary>
    public HashSet<string> DisabledHarnesses { get; set; } = [];

    /// <summary>
    /// User-added process exe names to treat as harnesses (e.g. "myagent.exe").
    /// Stored lower-case; the classifier matches them case-insensitively.
    /// </summary>
    public List<string> CustomHarnessExes { get; set; } = [];

    // ── Escalation thresholds ────────────────────────────────────────────────

    /// <summary>Medium-severity alerts before escalating to Alert level (per harness session).</summary>
    public int AlertLevelMediumCount { get; set; } = 3;

    /// <summary>High-severity alerts before escalating to Alarm level.</summary>
    public int AlarmLevelHighCount { get; set; } = 2;

    /// <summary>Unique rule IDs fired before escalating to Alarm level.</summary>
    public int AlarmLevelUniqueRules { get; set; } = 5;

    /// <summary>Distinct threat categories touched before escalating to Alarm level.</summary>
    public int AlarmLevelCategories { get; set; } = 3;

    /// <summary>Total alerts from one harness before escalating to Emergency level.</summary>
    public int EmergencyLevelTotalAlerts { get; set; } = 10;

    /// <summary>
    /// Rule IDs that unconditionally trigger Emergency escalation (no count threshold).
    /// Covers the most dangerous single-action patterns: credential dumping, ransomware
    /// indicators, remote code execution, UAC bypass, and administrator escalation.
    /// </summary>
    public string[] EmergencyRuleIds { get; set; } =
    [
        // Credential theft
        "cred-004",   // mimikatz
        "cred-005",   // LSASS dump
        "cred-018",   // DCSync / AD attack
        "cred-019",   // lateral movement (CrackMapExec / Impacket)

        // Ransomware indicators
        "win-009",    // VSS shadow copy deletion (windows-specific)
        "priv-003",   // VSS deletion (privilege-escalation duplicate pattern)

        // Remote code execution
        "net-001",    // curl|bash
        "net-002",    // PowerShell IEX from web
        "net-005",    // Python reverse shell
        "net-008",    // mshta remote HTA
        "net-009",    // regsvr32 Squiblydoo

        // Privilege escalation
        "priv-002",   // add user to Administrators group
        "priv-004",   // disable Windows Defender
        "priv-008",   // UAC bypass via fodhelper/eventvwr
        "priv-010",   // modify sudoers (NOPASSWD)
    ];

    public LlmTriageSettings LlmTriage { get; set; } = new();

    /// <summary>
    /// Proactive cross-harness auditing — periodically have a different connected model review a harness's
    /// recent behavior, on a cadence (events and/or minutes). Auditor chosen via <see cref="LlmTriage"/>
    /// (auditor != audited). See <see cref="ScheduledAuditSettings"/>. Off by default.
    /// </summary>
    public ScheduledAuditSettings ScheduledAudit { get; set; } = new();

    /// <summary>
    /// Operator-configured automatic responses per escalation tier (Ask Harness / Adversarial Audit /
    /// Request self-cleanup). Guardrailed by <see cref="Foreman.Core.Alerts.AlertResponsePolicy"/>:
    /// only these non-destructive actions are possible — no auto-kill or auto-mute.
    /// </summary>
    public Foreman.Core.Alerts.AlertResponseSettings AlertResponses { get; set; } = new();

    /// <summary>
    /// Game mode: when a fullscreen game/app is detected, pause TraceBrake's on-screen popups + alarm windows
    /// (it keeps detecting/logging silently and shows a digest when you exit). See
    /// <see cref="Foreman.Core.Models.GameModePolicy"/>.
    /// </summary>
    public Foreman.Core.Models.GameModeSettings GameMode { get; set; } = new();

    /// <summary>
    /// Decoy ("canary") credential files — opt-in honeytokens planted at credential paths you don't use, so
    /// the Miasma-style harvester's own enumeration trips a near-zero-false-positive alert. See
    /// <see cref="Foreman.Core.Security.DecoyCredentialSettings"/>.
    /// </summary>
    public Foreman.Core.Security.DecoyCredentialSettings DecoyCredentials { get; set; } = new();

    /// <summary>
    /// Presence lock (P3): require a hardware user-presence tap (Hello/PIN/passkey/YubiKey/U2F) for
    /// watchdog-weakening actions, so a same-user agent can't silently blind Foreman. Off until enrolled.
    /// See <see cref="Foreman.Core.Security.PresenceLockSettings"/> + <see cref="Foreman.Core.Security.PresenceLockPolicy"/>.
    /// </summary>
    public Foreman.Core.Security.PresenceLockSettings PresenceLock { get; set; } = new();

    /// <summary>
    /// Credential-sweep burst aggregator: when one harness tree reads this many DISTINCT credential stores
    /// within <see cref="CredentialSweepWindowSeconds"/>, TraceBrake fires a single Critical "credential-store
    /// sweep" alert — the Miasma harvester fingerprint. Each individual read still alerts on its own.
    /// </summary>
    public int CredentialSweepDistinctThreshold { get; set; } = 4;
    public int CredentialSweepWindowSeconds { get; set; } = 60;

    // ── Per-harness Trust ────────────────────────────────────────────────────

    /// <summary>
    /// Per-harness Trust level (1=locked-down … 5=hands-off) that applies a <see cref="TrustPreset"/> over the
    /// global baseline. Absent = level 3 = today's global behavior (so nothing changes until a slider moves).
    /// Keyed by harness Id (KnownHarnesses Id or "custom:exe.exe"), case-insensitive — the same key as
    /// <see cref="DisabledHarnesses"/> and BehaviorTracker's harness key.
    /// </summary>
    public Dictionary<string, int> HarnessTrust { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Shared Trust 1–5 capability profiles. A harness inherits the profile selected by <see cref="HarnessTrust"/>;
    /// the legacy per-harness restriction dictionary below remains a restrictive override for compatibility.
    /// </summary>
    public UniversalTrustSettings UniversalTrust { get; set; } = new();

    /// <summary>Effective escalation thresholds for a harness: its Trust preset over the global baseline, or
    /// the global baseline when no Trust override is set. Consumed by BehaviorTracker per harness.</summary>
    public EscalationThresholds EffectiveThresholds(string harnessId)
        => HarnessTrust.TryGetValue(harnessId, out var lvl)
            ? TrustPreset.Thresholds(lvl, this)
            : EscalationThresholds.FromGlobal(this);

    /// <summary>
    /// How long an unanswered "Ask Harness" request stays <c>pending</c> before TraceBrake ages it out to
    /// <c>expired</c> — the harness never connected, disconnected mid-request, or ignored the prompt. Expired
    /// requests are logged (never silently dropped) and a late reply is still accepted. <c>0</c> disables
    /// expiry (requests dangle until the count cap evicts them, the old behavior). Default 30 minutes.
    /// </summary>
    public int AskHarnessTimeoutMinutes { get; set; } = 30;

    /// <summary>
    /// Peer-PID binding for per-harness MCP tokens: TraceBrake attributes the connecting loopback process
    /// (peer-PID → harness) and compares it to the token's claimed harness. A MISMATCH (process X replayed
    /// harness Y's token) is ALWAYS logged Critical. This flag controls whether a mismatch is also BLOCKED
    /// (403). Default off (alert-only) so attribution accuracy can be observed on real connectors before
    /// enforcing — flip on once trusted. Match and unattributed (lookup miss / race) are always allowed.
    /// </summary>
    public bool McpPeerBindingEnforce { get; set; } = false;

    /// <summary>
    /// Adaptive noise reduction: learn from the OPERATOR's dismissals (UI acks) and SUGGEST quieting an
    /// operational alert class (hang/orphan/idle/nonzero-exit) that's repeatedly dismissed. Never auto-relaxes,
    /// never the security set, never learns from the agent's own behaviour. See <see cref="Alerts.SuppressionAdvisor"/>.
    /// </summary>
    public Alerts.AdaptiveAlertSettings AdaptiveAlerts { get; set; } = new();

    /// <summary>
    /// Notification cadence governor: caps bursts of OPERATIONAL toasts (hang/orphan) per harness into a few
    /// popups plus a periodic rollup, instead of dozens. Governs the TOAST only — every raw event is still
    /// logged — and never touches security/Critical alerts (those always notify individually, so a flood can't
    /// be used to bury a real signal). See <see cref="Alerts.AlertCadenceGovernor"/>.
    /// </summary>
    public Alerts.CadenceGovernorSettings CadenceGovernor { get; set; } = new();

    /// <summary>
    /// Context-scales the hang/idle timeout by operator presence (system last-input idle time) and harness
    /// task-activity, so a fixed no-I/O rule stops mislabelling expected-idle processes (an agent parked while
    /// the human is away) as hung. Monotonic: only ever LENGTHENS the threshold, capped by a multiplier and an
    /// absolute ceiling — operational-only, never the security set. See <see cref="Alerts.IdleThresholdPolicy"/>.
    /// </summary>
    public Alerts.IdleThresholdScalingSettings IdleThresholdScaling { get; set; } = new();

    /// <summary>
    /// Dead-man's switch (#62): when the operator is absent past a window while agents run, raise an
    /// "operating unattended" notice. Opt-in. See <see cref="Security.DeadMansSwitchPolicy"/>.
    /// </summary>
    public Security.DeadMansSwitchSettings DeadMansSwitch { get; set; } = new();

    /// <summary>
    /// OS-event-log blackbox handoff: mirror lifecycle (start/stop/crash) + security-significant events to the
    /// host OS event log (Windows Event Log / Linux journald) so TraceBrake's own record survives the app being
    /// killed or its files tampered. See <see cref="Notifications.OsEventLogForwarder"/>.
    /// </summary>
    public Notifications.OsEventLogSettings OsEventLog { get; set; } = new();

    /// <summary>
    /// Per-harness enabled "modalities" — the restricted system prompt: which basic, tiny-model-friendly
    /// operations (log-report, self-check, …) a harness is instructed to honour, delivered over MCP. Absent →
    /// the default agent-facing set, so nothing changes until set. Keyed by harness Id, case-insensitive.
    /// Editing this is a lock-protected action (P3). (Closed-loop spec.)
    /// </summary>
    public Dictionary<string, List<string>> HarnessModalities { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The agent-facing modality ids a harness honours: its explicit selection, or the default set.</summary>
    public IReadOnlyList<string> EnabledModalities(string harnessId)
        => HarnessModalities.TryGetValue(harnessId, out var ids) && ids.Count > 0
            ? ids
            : Foreman.Core.Mcp.ModalityCatalog.DefaultAgentModalities;

    /// <summary>Effective graded browser/desktop/ADB policy for this harness and its selected Trust level.</summary>
    public TrustCapabilityProfile EffectiveTrustCapabilities(string harnessId)
    {
        var level = HarnessTrust.TryGetValue(harnessId, out var configured) ? Math.Clamp(configured, 1, 5) : 3;
        var universal = (UniversalTrust ?? new UniversalTrustSettings()).ForLevel(level);
        HarnessCapabilityRestrictions.TryGetValue(harnessId, out var legacy);
        return universal.ApplyLegacyRestrictions(legacy);
    }

    /// <summary>
    /// Per-harness restrictions for high-risk MCP capability classes. TraceBrake can enforce these immediately for
    /// Foreman-brokered tools such as LiveWeave browser driving; third-party MCP servers are reported and the
    /// policy is delivered to the harness until a dedicated computer-use broker can enforce it directly.
    /// </summary>
    public Dictionary<string, Foreman.Core.Mcp.HarnessCapabilityRestrictions> HarnessCapabilityRestrictions { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    public Foreman.Core.Mcp.HarnessCapabilityRestrictions EffectiveCapabilityRestrictions(string harnessId)
        => Foreman.Core.Mcp.HarnessCapabilityPolicy.Effective(HarnessCapabilityRestrictions, harnessId);
}

public sealed class AdbBridgeSettings
{
    /// <summary>Off by default. Changes are revoked and re-applied live after a successful settings save.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Absolute operator-selected path to adb/adb.exe. TraceBrake never searches PATH because an agent-controlled PATH
    /// entry could turn bridge activation into arbitrary process execution.
    /// </summary>
    public string? ExecutablePath { get; set; }

    /// <summary>
    /// SHA-256 of the operator-enrolled adb binary. The runner verifies it and keeps the file write/delete-locked while
    /// TraceBrake is active, so a same-user process cannot replace the trusted executable after enrolment.
    /// </summary>
    public string? ExecutableSha256 { get; set; }

    /// <summary>Device serials the operator explicitly enrolled. Empty means inventory only.</summary>
    public List<string> EnrolledDeviceSerials { get; set; } = [];
}

public sealed class LlmTriageSettings
{
    public bool Enabled { get; set; } = true;
    public bool PreventSelfAudit { get; set; } = true;
    public int MaxEventsPerReview { get; set; } = 20;
    public List<AuditorPreference> AuditorPreferences { get; set; } =
    [
        new()
        {
            AuditorId = "codex",
            AuditorType = "harness",
            DisplayName = "Codex",
            TargetHarnessIds = ["claude-code", "cursor", "opencode", "t3-code"],
            MinimumSeverities = ["High", "Critical"],
            Priority = 100,
        },
        new()
        {
            AuditorId = "claude-code",
            AuditorType = "harness",
            DisplayName = "Claude Code",
            TargetHarnessIds = ["codex", "cursor", "opencode", "t3-code"],
            MinimumSeverities = ["High", "Critical"],
            Priority = 100,
        },
        new()
        {
            AuditorId = "opencode",
            AuditorType = "harness",
            DisplayName = "OpenCode",
            TargetHarnessIds = ["claude-code", "codex", "cursor", "t3-code"],
            MinimumSeverities = ["High", "Critical"],
            Priority = 100,
        },
    ];

    /// <summary>
    /// Picks the preferred auditor for reviewing <paramref name="targetHarnessId"/> at the given severity:
    /// the highest-priority enabled preference whose targets include it and whose minimum severity it
    /// meets, with self-audit excluded when <see cref="PreventSelfAudit"/> is set. Null when triage is
    /// off or nothing matches. Pure (preference match only) — delivery handles connected-or-not.
    /// </summary>
    public AuditorPreference? SelectAuditor(string targetHarnessId, Foreman.Core.Models.ForemanSeverity severity)
    {
        if (!Enabled || string.IsNullOrWhiteSpace(targetHarnessId)) return null;
        return AuditorPreferences
            .Where(p => p.Enabled)
            .Where(p => !PreventSelfAudit || !string.Equals(p.AuditorId, targetHarnessId, StringComparison.OrdinalIgnoreCase))
            .Where(p => p.TargetHarnessIds.Contains(targetHarnessId, StringComparer.OrdinalIgnoreCase))
            .Where(p => MeetsMinimumSeverity(p.MinimumSeverities, severity))
            .OrderByDescending(p => p.Priority)
            .FirstOrDefault();
    }

    private static bool MeetsMinimumSeverity(string[] minimums, Foreman.Core.Models.ForemanSeverity severity)
    {
        if (minimums.Length == 0) return true;   // no floor configured = handles anything
        foreach (var m in minimums)
            if (Enum.TryParse<Foreman.Core.Models.ForemanSeverity>(m, ignoreCase: true, out var min) && severity >= min)
                return true;
        return false;
    }

    /// <summary>
    /// Ensures <paramref name="auditorId"/> is the preferred harness reviewer for alerts from
    /// <paramref name="targetHarnessId"/>. Updates an existing preference for the same auditor or
    /// appends a new one.
    /// </summary>
    public void UpsertAuditorPreference(string targetHarnessId, string auditorId, string? displayName = null)
    {
        if (string.IsNullOrWhiteSpace(targetHarnessId) || string.IsNullOrWhiteSpace(auditorId))
            return;

        var existing = AuditorPreferences.FirstOrDefault(p =>
            p.Enabled &&
            string.Equals(p.AuditorId, auditorId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(p.AuditorType, "harness", StringComparison.OrdinalIgnoreCase));

        if (existing is not null)
        {
            if (!existing.TargetHarnessIds.Contains(targetHarnessId, StringComparer.OrdinalIgnoreCase))
                existing.TargetHarnessIds = [.. existing.TargetHarnessIds, targetHarnessId];
            if (!string.IsNullOrWhiteSpace(displayName))
                existing.DisplayName = displayName;
            return;
        }

        var known = Foreman.Core.Models.KnownHarnesses.GetById(auditorId);
        AuditorPreferences.Add(new AuditorPreference
        {
            AuditorId = auditorId,
            AuditorType = "harness",
            DisplayName = displayName ?? known?.DisplayName ?? auditorId,
            TargetHarnessIds = [targetHarnessId],
            MinimumSeverities = ["High", "Critical"],
            Priority = 100,
        });
    }
}

public sealed class AuditorPreference
{
    public bool Enabled { get; set; } = true;
    public string AuditorId { get; set; } = string.Empty;
    /// <summary>harness | api</summary>
    public string AuditorType { get; set; } = "harness";
    public string DisplayName { get; set; } = string.Empty;
    public string[] TargetHarnessIds { get; set; } = [];
    public string[] MinimumSeverities { get; set; } = ["High", "Critical"];
    public int Priority { get; set; } = 100;
    public string? ApiEndpoint { get; set; }
    public string? Model { get; set; }
}
