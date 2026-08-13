namespace Foreman.Core.Integration;

/// <summary>One connectable harness: its id/display name plus the delegates to check, detect-install, and (re)write its MCP config.</summary>
public sealed record HarnessConnector(
    string HarnessId,
    string DisplayName,
    Func<int, bool> IsConfigured,
    Func<int, string, ConnectResult> Connect,
    Func<bool>? IsInstalled = null);

/// <summary>The outcome of re-issuing one harness's token.</summary>
public sealed record ReissueResult(string HarnessId, string DisplayName, ConnectStatus Status, string Message);

/// <summary>
/// Registry of the harnesses TraceBrake can write MCP config for, plus batch operations to (re)connect many at
/// once — the robust fix when per-harness tokens go stale, and the one-click "connect everything" path.
///
/// Per-harness tokens are HMAC'd over the install secret (<c>mcp.token</c>); if that secret is rotated (the file
/// is deleted/regenerated) every previously-written token silently 401s. Each connector's <c>Connect</c> always
/// OVERWRITES its entry with a freshly-minted token, so re-running it for a client repairs it. (T3 Code is
/// intentionally absent — it drives an underlying agent and has no MCP config of its own.)
/// </summary>
public static class HarnessConnectors
{
    public static readonly IReadOnlyList<HarnessConnector> All =
    [
        new("claude-code",    "Claude Code",        p => ClaudeMcpConnector.IsConfigured(p),    (p, t) => ClaudeMcpConnector.Connect(p, t),    () => Installed(ClaudeMcpConnector.DefaultConfigPath)),
        new("codex",          "Codex",              p => CodexMcpConnector.IsConfigured(p),     (p, t) => CodexMcpConnector.Connect(p, t),     () => Installed(CodexMcpConnector.DefaultConfigPath)),
        new("cursor",         "Cursor",             p => CursorMcpConnector.IsConfigured(p),    (p, t) => CursorMcpConnector.Connect(p, t),    () => Installed(CursorMcpConnector.DefaultConfigPath)),
        new("opencode",       "OpenCode",           p => OpenCodeMcpConnector.IsConfigured(p),  (p, t) => OpenCodeMcpConnector.Connect(p, t),  () => OpenCodeMcpConnector.CandidatePaths().Any(Installed)),
        new("github-copilot", "GitHub Copilot CLI", p => CopilotMcpConnector.IsConfigured(p),   (p, t) => CopilotMcpConnector.Connect(p, t),   () => Installed(CopilotMcpConnector.DefaultConfigPath)),
        new("gemini-cli",     "Gemini CLI",         p => GeminiMcpConnector.IsConfigured(p),    (p, t) => GeminiMcpConnector.Connect(p, t),    () => Installed(GeminiMcpConnector.DefaultConfigPath)),
        new("lm-studio",      "LM Studio",          p => LmStudioMcpConnector.IsConfigured(p),  (p, t) => LmStudioMcpConnector.Connect(p, t),  () => Installed(LmStudioMcpConnector.DefaultConfigPath)),
    ];

    /// <summary>
    /// For every harness whose config currently points at Foreman, mint a fresh per-harness token and overwrite
    /// its entry — repairing stale tokens. <paramref name="mint"/> is the running server's MintHarnessToken.
    /// Returns one result per re-issued harness (unconfigured ones are skipped). Never throws: a connector whose
    /// probe or write fails is reported as <see cref="ConnectStatus.Failed"/> rather than aborting the batch.
    /// </summary>
    public static IReadOnlyList<ReissueResult> ReissueConfigured(
        int port, Func<string, string> mint, IReadOnlyList<HarnessConnector>? connectors = null)
    {
        var results = new List<ReissueResult>();
        foreach (var c in connectors ?? All)
        {
            if (!SafeBool(() => c.IsConfigured(port))) continue;   // can't read / not pointed at TraceBrake → leave alone
            results.Add(RunConnect(c, port, mint));
        }
        return results;
    }

    /// <summary>
    /// One-click "connect everything": writes (or refreshes) the TraceBrake MCP entry — with a fresh scoped token —
    /// for every agent that is (a) currently running (its harness id is in <paramref name="runningHarnessIds"/>),
    /// (b) already configured here, or (c) installed on this machine (its config file/dir exists). This both
    /// connects not-yet-wired agents AND repairs stale tokens on configured ones, in a single pass. Agents that
    /// are none of running/configured/installed are skipped, so TraceBrake never litters config for tools you don't
    /// use. Never throws: a connector whose probe or write fails is reported as <see cref="ConnectStatus.Failed"/>.
    ///
    /// Note: this writes the config; the agent itself opens the MCP session on its NEXT start/restart — Foreman
    /// can't force a running client to dial in.
    /// </summary>
    public static IReadOnlyList<ReissueResult> ConnectDetectedAndInstalled(
        int port, Func<string, string> mint,
        IReadOnlyCollection<string>? runningHarnessIds = null,
        IReadOnlyList<HarnessConnector>? connectors = null)
    {
        var running = runningHarnessIds is null or { Count: 0 }
            ? null
            : new HashSet<string>(runningHarnessIds, StringComparer.OrdinalIgnoreCase);

        var results = new List<ReissueResult>();
        foreach (var c in connectors ?? All)
        {
            var relevant =
                (running?.Contains(c.HarnessId) ?? false)               // TraceBrake sees it running now
                || SafeBool(() => c.IsConfigured(port))                 // already points at TraceBrake (repairs a stale token)
                || SafeBool(() => c.IsInstalled?.Invoke() ?? false);    // installed on disk but not yet connected
            if (!relevant) continue;
            results.Add(RunConnect(c, port, mint));
        }
        return results;
    }

    private static ReissueResult RunConnect(HarnessConnector c, int port, Func<string, string> mint)
    {
        ConnectResult r;
        try { r = c.Connect(port, mint(c.HarnessId)); }
        catch (Exception ex) { r = new ConnectResult(ConnectStatus.Failed, ex.Message); }
        return new ReissueResult(c.HarnessId, c.DisplayName, r.Status, r.Message);
    }

    /// <summary>
    /// "Installed" heuristic: the agent has created its own config file, or its dedicated config directory exists.
    /// Configs that live directly in the home root (e.g. <c>~/.claude.json</c>) can't use the directory signal —
    /// the home dir always exists — so for those we require the file itself.
    /// </summary>
    private static bool Installed(string configPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(configPath)) return false;
            if (File.Exists(configPath)) return true;
            var dir = Path.GetDirectoryName(configPath);
            if (string.IsNullOrEmpty(dir)) return false;
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (SamePath(dir, home)) return false;   // config sits in the home root → require the file itself
            return Directory.Exists(dir);
        }
        catch { return false; }
    }

    private static bool SamePath(string a, string b)
    {
        try
        {
            var na = Path.TrimEndingDirectorySeparator(Path.GetFullPath(a));
            var nb = Path.TrimEndingDirectorySeparator(Path.GetFullPath(b));
            return string.Equals(na, nb,
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        }
        catch { return false; }
    }

    private static bool SafeBool(Func<bool> probe) { try { return probe(); } catch { return false; } }
}
