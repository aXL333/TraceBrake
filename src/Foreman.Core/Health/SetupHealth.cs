namespace Foreman.Core.Health;

/// <summary>How a setup-health row renders: green (working), amber (configured but not delivering — act),
/// gray (feature off / not set up — optional), blue (neutral fact, nothing to fix).</summary>
public enum SetupHealthStatus { Ok, Attention, Off, Info }

/// <summary>One row of the checklist: what it is, how it's doing, and — when actionable — what to do.</summary>
public sealed record SetupHealthItem(string Title, SetupHealthStatus Status, string Detail, string? Remedy = null);

/// <summary>
/// Plain data snapshot of everything the checklist judges, gathered by the App at refresh time. Keeping it
/// dumb (bools/counts/strings) is what makes <see cref="SetupHealth.Evaluate"/> pure and unit-testable.
/// </summary>
public sealed record SetupHealthSnapshot
{
    // Launch context
    public string? DataDirRedirectedTo { get; init; }

    // MCP surface
    public bool McpListening { get; init; }
    public int McpPort { get; init; }
    public int ConnectedMcpClients { get; init; }
    public IReadOnlyList<string> ConnectedClientNames { get; init; } = [];

    // Browser extension
    public bool ExtensionPaired { get; init; }

    // Presence lock (Windows Hello / FIDO2)
    public bool PresenceEnrolled { get; init; }

    // Vault
    public bool VaultEnrolled { get; init; }
    public bool VaultUnlocked { get; init; }
    public int PendingDeposits { get; init; }
    public bool DepositKeyTampered { get; init; }

    // Decoy credentials
    public bool DecoysEnabled { get; init; }
    public int DecoysPlanted { get; init; }
    public bool ReadAuditingEnabled { get; init; }
    public bool SidecarConnected { get; init; }
    public int DecoyAuditExpected { get; init; }
    public int DecoyAuditArmed { get; init; }

    // Hardening / blackbox
    public bool GuardianInstalled { get; init; }
    /// <summary>"publisher_signed", "path_hash_pinned", or "legacy_or_unavailable".</summary>
    public string GuardianTrustMode { get; init; } = string.Empty;
    public bool OsEventLogAvailable { get; init; }
}

/// <summary>
/// Turns a <see cref="SetupHealthSnapshot"/> into the ordered checklist. The ORDER is deliberate: integrity
/// of the launch context first (everything below lies if the data dir is an overlay copy), then the agent
/// plumbing (MCP, extension), then the security features in the order an operator sets them up.
/// </summary>
public static class SetupHealth
{
    public static IReadOnlyList<SetupHealthItem> Evaluate(SetupHealthSnapshot s)
    {
        var items = new List<SetupHealthItem>();

        // 1. Launch context — if this is wrong, every other row describes the WRONG install's state.
        items.Add(s.DataDirRedirectedTo is { Length: > 0 } overlay
            ? new("Launch context", SetupHealthStatus.Attention,
                $"Data directory is redirected to a sandbox overlay: {overlay}. This instance runs on a COPY of TraceBrake's real state.",
                "Close this instance and start TraceBrake from the tray, Explorer, or its shortcut.")
            : new("Launch context", SetupHealthStatus.Ok, "Data directory resolves normally (no sandbox overlay)."));

        // 2. MCP server — the bridge every harness integration rides on.
        items.Add(s.McpListening
            ? new("MCP server", SetupHealthStatus.Ok, $"Listening on 127.0.0.1:{s.McpPort}.")
            : new("MCP server", SetupHealthStatus.Attention, $"Not listening on port {s.McpPort}.",
                "Another process may hold the port — change the port in Settings or free it, then restart TraceBrake (the app)."));

        // 3. Connected agents.
        items.Add(s.ConnectedMcpClients > 0
            ? new("Connected agents", SetupHealthStatus.Ok,
                $"{s.ConnectedMcpClients} client(s): {string.Join(", ", s.ConnectedClientNames)}.")
            : new("Connected agents", SetupHealthStatus.Info, "No agent harness is connected right now.",
                "Open Connect Agent to pair a harness (Claude Code, Codex, Cursor…)."));

        // 4. Browser extension.
        items.Add(s.ExtensionPaired
            ? new("Browser extension", SetupHealthStatus.Ok, "Paired.")
            : new("Browser extension", SetupHealthStatus.Off, "Not paired — browser-use mediation and vault browser fills are unavailable.",
                "Open Connect Agent and pair the extension from its side panel."));

        // 5. Presence lock — gates every weakening action and every agent credential release.
        items.Add(s.PresenceEnrolled
            ? new("Presence lock", SetupHealthStatus.Ok, "Enrolled — weakening actions require a Windows Hello / security-key tap.")
            : new("Presence lock", SetupHealthStatus.Off, "Not enrolled — settings can be weakened without a physical tap, and agent vault releases are blocked.",
                "Enroll in Settings → Presence lock (Windows Hello or a FIDO2 key)."));

        // 6. Vault.
        if (!s.VaultEnrolled)
            items.Add(new("Vault", SetupHealthStatus.Off, "No vault enrolled — agents cannot use stored credentials or self-signup.",
                "Enroll via tray → Vault… (choose a master password)."));
        else
            items.Add(s.VaultUnlocked
                ? new("Vault", SetupHealthStatus.Ok, "Enrolled and unlocked.")
                : new("Vault", SetupHealthStatus.Info, "Enrolled, currently locked. Agent sign-ups are queued encrypted until you unlock."));

        // 6b. Locked-time deposits — only meaningful once a vault exists.
        if (s.VaultEnrolled && s.DepositKeyTampered)
            items.Add(new("Sign-up deposits", SetupHealthStatus.Attention,
                "The deposit public key on disk does NOT match the sealed copy — a swap. Queued deposits must not be trusted.",
                "Review the HIGH alert in the event log; do not accept pending sign-ups."));
        else if (s.VaultEnrolled && s.PendingDeposits > 0)
            items.Add(new("Sign-up deposits", SetupHealthStatus.Attention,
                $"{s.PendingDeposits} locked-time sign-up(s) awaiting review.",
                "Unlock the vault, then tray → Review pending sign-ups…"));

        // 7. Decoy credentials.
        if (!s.DecoysEnabled)
            items.Add(new("Decoy credentials", SetupHealthStatus.Off, "Disabled — no honeytoken tripwires are planted.",
                "Enable in Settings → Decoy credentials."));
        else if (s.DecoysPlanted == 0)
            items.Add(new("Decoy credentials", SetupHealthStatus.Attention,
                "Enabled but ZERO decoys are tracked — the tripwire is armed on paper only.",
                "Re-apply the decoy plant from Settings (existing TraceBrake decoys on disk are adopted)."));
        else if (s.ReadAuditingEnabled &&
                 (s.DecoyAuditExpected <= 0 || s.DecoyAuditArmed < s.DecoyAuditExpected))
            items.Add(new("Decoy credentials", SetupHealthStatus.Attention,
                $"{s.DecoysPlanted} decoy(s) are tracked, but only {s.DecoyAuditArmed} of " +
                $"{Math.Max(s.DecoyAuditExpected, s.DecoysPlanted)} expected tripwire(s) are armed.",
                "Re-apply decoy auditing and review the High monitoring notice."));
        else
            items.Add(new("Decoy credentials", SetupHealthStatus.Ok, $"{s.DecoysPlanted} decoy(s) planted and tracked."));

        // 7b. Read-auditing rides the elevated sidecar; enabled-but-disconnected means no SACL tripwire is live.
        // NOTE the honest limit: a connected sidecar proves the auditor is RUNNING, not that Security 4663 events
        // actually flow — Group Policy / Advanced Audit Policy can override `auditpol` so the SACL is set but no
        // event fires. In-process TraceBrake can't see that; only a live read test can. So don't claim "working".
        if (s.DecoysEnabled && s.ReadAuditingEnabled)
            items.Add(s.SidecarConnected && s.DecoyAuditExpected > 0 &&
                      s.DecoyAuditArmed == s.DecoyAuditExpected
                ? new("Decoy read-auditing", SetupHealthStatus.Ok,
                    "Elevated sidecar connected — direct reads of bait decoys should alert. If a known decoy read does NOT alert, " +
                    "the OS audit policy may be overridden (Group Policy); run the decoy self-test to confirm 4663 events actually flow.")
                : new("Decoy read-auditing", SetupHealthStatus.Attention,
                    $"Enabled, but only {s.DecoyAuditArmed} of {Math.Max(s.DecoyAuditExpected, s.DecoysPlanted)} expected " +
                    "tripwire(s) are armed; connectivity alone is not treated as coverage.",
                    "Re-apply in Settings and accept the UAC prompt (and check nothing tracked is planted: see the decoys row)."));
        else if (s.DecoysEnabled)
            items.Add(new("Decoy read-auditing", SetupHealthStatus.Off,
                "Off — only command-line sentinel detection covers the decoys (direct file reads go unseen).",
                "Enable \"audit READS of decoys\" in Settings (needs the elevated sidecar; one UAC)."));

        // 8. Hardened guardian (optional prevention tier).
        items.Add(!s.GuardianInstalled
            ? new("Hardened guardian", SetupHealthStatus.Off,
                "Not installed — tamper-evidence seals rest on per-user keys (detection, not prevention).",
                "Optional: Settings → Enable hardened guardian (one UAC).")
            : s.GuardianTrustMode == "publisher_signed"
                ? new("Hardened guardian", SetupHealthStatus.Ok,
                    "SYSTEM key-holder is active and callers are authenticated to the verified TraceBrake publisher.")
                : s.GuardianTrustMode == "path_hash_pinned"
                    ? new("Hardened guardian", SetupHealthStatus.Attention,
                        "Unsigned development mode: SYSTEM key-holder callers are pinned by TraceBrake.exe path and SHA-256, not by publisher.",
                        "This is stronger than broad local-user trust, but not a commercial hardening boundary. Re-enable after signing to upgrade automatically to publisher trust.")
                    : new("Hardened guardian", SetupHealthStatus.Attention,
                        "The installed service is legacy, unavailable, or does not report an authenticated client policy. TraceBrake is ignoring it.",
                        "Disable and re-enable the guardian to install the current authenticated protocol."));

        // 9. OS event log blackbox.
        items.Add(s.OsEventLogAvailable
            ? new("OS event log", SetupHealthStatus.Ok, "Registered — lifecycle and rollback witnesses are durably recorded outside Foreman.")
            : new("OS event log", SetupHealthStatus.Attention,
                "Source not registered — no external blackbox record, and rollback detection loses its witness.",
                "Enable Run Elevated once in Settings to register the event source."));

        return items;
    }
}
