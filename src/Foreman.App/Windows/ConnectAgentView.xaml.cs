using Foreman.Core.Events;
using Foreman.Core.Integration;
using Foreman.Core.Models;
using Foreman.McpServer;
using System.Windows;
using System.Windows.Controls;

namespace Foreman.App.Windows;

/// <summary>
/// Beginner-friendly "connect your agent" guide. Shows who's connected now (with sampling capability),
/// one-click connect for Claude Code and Codex, and copy-paste self-config
/// (URL + Authorization header, token filled in) for any other MCP client. Hosted as the Dashboard "Connect"
/// tab (was a standalone window).
/// </summary>
public partial class ConnectAgentView : UserControl
{
    private readonly int _port;
    private readonly string _token;          // raw install token (operator/unscoped) — used for the generic path
    private readonly Func<string, string> _mint;   // mints a per-harness (scoped) token
    private readonly Func<IReadOnlyList<McpClientInfo>>? _getClients;
    private readonly Func<string>? _beginPairing;   // begins extension pairing, returns the on-screen code
    private readonly Func<IReadOnlyCollection<string>>? _getRunningHarnessIds;   // harness ids TraceBrake sees running now
    private readonly Func<bool>? _isLiveWeaveConnected;   // true when the LiveWeave extension has checked in recently

    /// <summary>Reads/sets the mediated computer-use (cu_*) driver harness; wired by TrayController to the
    /// in-process CuBroker after construction. Empty/null = operator only, "*" = any harness.</summary>
    public Func<string?>? GetCuDriver { get; set; }
    public Action<string?>? SetCuDriver { get; set; }

    public ConnectAgentView(int port, string token, Func<IReadOnlyList<McpClientInfo>>? getClients,
                              Func<string, string>? mintToken = null, Func<string>? beginPairing = null,
                              Func<IReadOnlyCollection<string>>? getRunningHarnessIds = null,
                              Func<bool>? isLiveWeaveConnected = null)
    {
        _port = port;
        _token = token;
        _mint = mintToken ?? (_ => token);   // fall back to the install token if minting isn't wired
        _getClients = getClients;
        _beginPairing = beginPairing;
        _getRunningHarnessIds = getRunningHarnessIds;
        _isLiveWeaveConnected = isLiveWeaveConnected;
        InitializeComponent();
        Populate();
        // The CU-driver callbacks are wired by the tray AFTER construction, so reflect the current driver once shown.
        Loaded += (_, _) => RefreshCuDriver();
    }

    // One row in the shared computer-use driver checklist. Plain mutable CLR object: the CheckBox TwoWay binding writes
    // IsChecked back on toggle; to reflect changes made in code we rebuild the list (reassign ItemsSource).
    private sealed class DriverChoice
    {
        public string Name { get; init; } = "";
        public bool IsChecked { get; set; }
    }

    // Candidate driver ids offered in the checklist ("any" = all harnesses), plus whatever TraceBrake sees running.
    private List<string> CuDriverCandidates()
    {
        var ids = new List<string> { "any", "claude-code", "codex", "cursor",
                                     "opencode", "github-copilot", "gemini-cli", "lm-studio", "t3-code" };
        foreach (var id in _getRunningHarnessIds?.Invoke() ?? [])
            if (!string.IsNullOrWhiteSpace(id) && !ids.Contains(id, StringComparer.OrdinalIgnoreCase))
                ids.Add(id.Trim().ToLowerInvariant());
        return ids;
    }

    // Parse the broker's driver string (null = operator-only, "*" = any, else comma-joined) into a checked set.
    private static HashSet<string> ParseDriverSet(string? driver)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(driver)) return set;
        if (driver == "*") { set.Add("any"); return set; }
        foreach (var id in driver.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            set.Add(id);
        return set;
    }

    private void PopulateCuDriverChoices() => RefreshCuDriver();

    // Apply the ticked harnesses as the driver set. Joining with commas and reusing the single-string SetCuDriver
    // wire keeps the App/tray/MCP plumbing unchanged (CuBroker.SetDriver splits the list back out).
    private void SetCuDriverClick(object sender, RoutedEventArgs e)
    {
        var chosen = (CuDriverList.ItemsSource as IEnumerable<DriverChoice> ?? [])
            .Where(c => c.IsChecked).Select(c => c.Name).ToList();
        SetCuDriver?.Invoke(string.Join(",", chosen));
        RefreshCuDriver();
    }

    private void RefreshCuDriver()
    {
        if (CuDriverStatus is null) return;
        var d = GetCuDriver?.Invoke();
        var authorized = ParseDriverSet(d);
        // Show every candidate, plus any authorized custom id not in the seed list; tick per current state.
        var names = CuDriverCandidates();
        foreach (var a in authorized)
            if (!names.Contains(a, StringComparer.OrdinalIgnoreCase)) names.Add(a);
        CuDriverList.ItemsSource = names
            .Select(n => new DriverChoice { Name = n, IsChecked = authorized.Contains(n) })
            .ToList();

        CuDriverStatus.Text = string.IsNullOrEmpty(d)
            ? "Current: operator only — no harness can drive browser or Android use yet."
            : d == "*" ? "Current: ANY connected harness may drive browser and Android use."
            : $"Current: {d.Replace(",", ", ")} may drive browser and Android use.";
    }

    // Each agent gets a scoped, per-harness token so it can only see/act on itself.
    private string ClaudeToken   => _mint("claude-code");
    private string CodexToken    => _mint("codex");
    private string CursorToken   => _mint("cursor");
    private string OpenCodeToken => _mint("opencode");
    private string CopilotToken  => _mint("github-copilot");
    private string GeminiToken   => _mint("gemini-cli");
    private string LmStudioToken => _mint("lm-studio");
    private string T3Token       => _mint("t3-code");

    private void Populate()
    {
        ClaudeJsonBox.Text = ClaudeMcpConnector.BuildClaudeConfigSnippet(_port, ClaudeToken);
        CodexTomlBox.Text = CodexMcpConnector.BuildConfigSnippet(_port, CodexToken);
        CursorJsonBox.Text = CursorMcpConnector.BuildConfigSnippet(_port, CursorToken);
        OpenCodeJsonBox.Text = OpenCodeMcpConnector.BuildConfigSnippet(_port, OpenCodeToken);
        CopilotJsonBox.Text = CopilotMcpConnector.BuildConfigSnippet(_port, CopilotToken);
        GeminiJsonBox.Text = GeminiMcpConnector.BuildConfigSnippet(_port, GeminiToken);
        LmStudioJsonBox.Text = LmStudioMcpConnector.BuildConfigSnippet(_port, LmStudioToken);
        T3Box.Text = ClaudeMcpConnector.BuildClaudeConfigSnippet(_port, T3Token);   // T3 uses the underlying agent's mcpServers shape
        GenericBox.Text =
            $"URL:    {ClaudeMcpConnector.Url(_port)}\r\n" +
            $"Header: Authorization: Bearer {_token}\r\n\r\n" +
            "Server entry (JSON):\r\n" +
            ClaudeMcpConnector.BuildServerEntrySnippet(_port, _token);
        TokenNote.Text =
            "Claude Code and Codex each get their own scoped token (they can only see themselves in TraceBrake). " +
            "The generic config above uses your full-access install token at %LocalAppData%\\TraceBrake\\mcp.token — " +
            "keep it private. /health is open; /mcp requires a token.";
        PopulateCuDriverChoices();
        RefreshConnected();
    }

    private void RefreshConnected()
    {
        var clients = _getClients?.Invoke() ?? [];
        // Collapse identical clients to ONE line: MCP clients (notably the browser extension) use short-lived
        // per-request sessions, so the raw list can carry dozens of duplicate entries for a single agent. Group
        // by identity and show a (×N) session count, so the count stays visible without flooding the header.
        ConnectedText.Text = clients.Count == 0
            ? "No agents are connected to TraceBrake yet. Connect one below, then restart it."
            : "Connected now:\n" + string.Join("\n", clients
                .GroupBy(c => (c.Name, c.Version, c.Sampling))
                .OrderBy(g => g.Key.Name, StringComparer.OrdinalIgnoreCase)
                .Select(g =>
                {
                    var ver = string.IsNullOrWhiteSpace(g.Key.Version) ? "" : $" v{g.Key.Version}";
                    var count = g.Count() > 1 ? $"  (×{g.Count()} sessions)" : "";
                    return $"  • {g.Key.Name}{ver} — sampling: {(g.Key.Sampling ? "yes" : "no")}{count}";
                }));

        RefreshLiveWeaveStatus();
    }

    private void RefreshLiveWeaveStatus()
    {
        if (LiveWeaveStatusText is null) return;
        var connected = _isLiveWeaveConnected?.Invoke() ?? false;
        LiveWeaveStatusText.Text = connected
            ? "● Connected — the LiveWeave builder is linked. Only the selected driver harness or operator token can drive it."
            : "○ Not connected — pair below, then choose LiveWeave mode in the browser extension options.";
    }

    private void ConnectClaudeClick(object sender, RoutedEventArgs e)
    {
        var r = ClaudeMcpConnector.Connect(_port, ClaudeToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Claude Code's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "TraceBrake — Connect Claude Code", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Claude Code to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "TraceBrake — Connect Claude Code", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectCodexClick(object sender, RoutedEventArgs e)
    {
        var r = CodexMcpConnector.Connect(_port, CodexToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Codex's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste TOML below instead.",
                "TraceBrake — Connect Codex", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nStart Codex in a NEW terminal to connect and load the TraceBrake " +
                "instructions (Codex reads the bearer token from the environment variable at launch)." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "TraceBrake — Connect Codex", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectCursorClick(object sender, RoutedEventArgs e)
    {
        var r = CursorMcpConnector.Connect(_port, CursorToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Cursor's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "TraceBrake — Connect Cursor", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Cursor, or refresh the legacy-compatible \"foreman\" server in Settings → Tools & MCP, to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "TraceBrake — Connect Cursor", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectOpenCodeClick(object sender, RoutedEventArgs e)
    {
        var r = OpenCodeMcpConnector.Connect(_port, OpenCodeToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update OpenCode's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "TraceBrake — Connect OpenCode", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart OpenCode to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "TraceBrake — Connect OpenCode", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectCopilotClick(object sender, RoutedEventArgs e)
    {
        var r = CopilotMcpConnector.Connect(_port, CopilotToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update GitHub Copilot CLI's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "TraceBrake — Connect Copilot CLI", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Copilot CLI (or run /mcp) to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "TraceBrake — Connect Copilot CLI", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectGeminiClick(object sender, RoutedEventArgs e)
    {
        var r = GeminiMcpConnector.Connect(_port, GeminiToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update Gemini CLI's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "TraceBrake — Connect Gemini CLI", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nRestart Gemini CLI to connect." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "TraceBrake — Connect Gemini CLI", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectLmStudioClick(object sender, RoutedEventArgs e)
    {
        var r = LmStudioMcpConnector.Connect(_port, LmStudioToken);
        if (r.Status == ConnectStatus.Failed)
            MessageBox.Show(
                $"Couldn't update LM Studio's config automatically:\n\n{r.Message}\n\n" +
                "Use the copy-paste JSON below instead.",
                "TraceBrake — Connect LM Studio", MessageBoxButton.OK, MessageBoxImage.Warning);
        else
            MessageBox.Show(
                $"{r.Message}\n\nLM Studio reloads mcp.json automatically. Caveat emptor: if LM Studio ignores " +
                "the Authorization header, TraceBrake will reject the connection — check LM Studio's MCP panel." +
                (r.BackupPath is { } b ? $"\n\nBackup saved: {b}" : ""),
                "TraceBrake — Connect LM Studio", MessageBoxButton.OK, MessageBoxImage.Information);
        RefreshConnected();
    }

    private void ConnectT3Click(object sender, RoutedEventArgs e)
    {
        // T3 Code is a control plane — it has no MCP config of its own; you point its underlying agent at
        // Foreman. So "connect automatically" copies the config + explains, rather than writing a file blind.
        Copy(T3Box.Text, "T3 Code config copied.");
        MessageBox.Show(
            "T3 Code runs an underlying agent (Claude Code, Codex, or OpenCode) and doesn't have its own MCP " +
            "config file. Connect that agent using its card above — T3 Code will use the same TraceBrake MCP " +
            "server, and TraceBrake monitors T3 Code itself as the control plane.\n\n" +
            "The config has been copied to your clipboard for whichever agent T3 Code drives.",
            "TraceBrake — Connect T3 Code", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CopyCliClick(object sender, RoutedEventArgs e) =>
        Copy(ClaudeMcpConnector.BuildCliCommand(_port, ClaudeToken), "CLI command copied — paste it into a terminal.");

    private void CopyCursorJsonClick(object sender, RoutedEventArgs e) =>
        Copy(CursorJsonBox.Text, "Cursor JSON copied.");

    private void CopyOpenCodeJsonClick(object sender, RoutedEventArgs e) =>
        Copy(OpenCodeJsonBox.Text, "OpenCode JSON copied.");

    private void CopyCopilotJsonClick(object sender, RoutedEventArgs e) =>
        Copy(CopilotJsonBox.Text, "Copilot CLI JSON copied.");

    private void CopyGeminiJsonClick(object sender, RoutedEventArgs e) =>
        Copy(GeminiJsonBox.Text, "Gemini CLI JSON copied.");

    private void CopyLmStudioJsonClick(object sender, RoutedEventArgs e) =>
        Copy(LmStudioJsonBox.Text, "LM Studio JSON copied.");

    private void CopyT3Click(object sender, RoutedEventArgs e) =>
        Copy(T3Box.Text, "T3 Code config copied.");

    private void CopyClaudeJsonClick(object sender, RoutedEventArgs e) =>
        Copy(ClaudeJsonBox.Text, "Claude Code JSON copied.");

    private void CopyCodexTomlClick(object sender, RoutedEventArgs e) =>
        Copy(CodexTomlBox.Text, "Codex TOML copied.");

    private void CopyGenericClick(object sender, RoutedEventArgs e) =>
        Copy(GenericBox.Text, "Config copied.");

    private void Copy(string text, string ok)
    {
        try { Clipboard.SetText(text); StatusText.Text = ok + "  Restart your agent to apply."; }
        catch (Exception ex) { StatusText.Text = "Couldn't copy to the clipboard: " + ex.Message; }
    }

    private void PairExtensionClick(object sender, RoutedEventArgs e) =>
        BeginPairingFlow(
            title: "TraceBrake — Pair browser extension",
            extraInstructions:
                "In the TraceBrake browser extension, open its Options page and paste this code within 2 minutes. " +
                "The code never leaves your machine — the extension proves it holds the code over a loopback " +
                "challenge/response.\n\n" +
                "The same code works for both the TraceBrake safety extension and LiveWeave — each declares which " +
                "harness it is when it pairs.");

    private void PairLiveWeaveClick(object sender, RoutedEventArgs e) =>
        BeginPairingFlow(
            title: "TraceBrake — Pair LiveWeave extension",
            extraInstructions:
                "Open the TraceBrake browser extension options, choose LiveWeave local page builder mode, set a driver " +
                "harness such as codex or claude-code, and enter this code within 2 minutes. The code never leaves " +
                "your machine; LiveWeave proves it holds the code over a loopback challenge/response.\n\n" +
                "Once linked, only the selected driver harness, or the operator token, can drive LiveWeave. " +
                "Empty driver means operator-only; 'any' is an explicit all-harness mode.",
            onPaired: RefreshLiveWeaveStatus);

    // Shared pairing entry point: mint an on-screen code, copy it, and explain where to type it. The pairing code
    // is harness-agnostic — the extension (safety or LiveWeave) declares its harnessId during /pair/complete — so
    // both "Pair…" buttons funnel through here with only the on-screen copy differing.
    private void BeginPairingFlow(string title, string extraInstructions, Action? onPaired = null)
    {
        if (_beginPairing is null)
        {
            MessageBox.Show(
                "Pairing isn't available yet — the MCP server is still starting. Try again in a moment.",
                title, MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var code = _beginPairing();
        var copied = false;
        try { Clipboard.SetText(code); copied = true; } catch { /* clipboard busy — code is still shown below */ }
        StatusText.Text = copied
            ? $"Pairing code {code} copied — enter it in the extension's Options page within 2 minutes."
            : $"Pairing code: {code} — enter it in the extension's Options page within 2 minutes.";
        MessageBox.Show(
            $"Pairing code:\n\n        {code}\n\n" +
            (copied ? "(Copied to your clipboard.) " : "") +
            extraInstructions,
            title, MessageBoxButton.OK, MessageBoxImage.Information);
        onPaired?.Invoke();
    }

    // One-click "connect everything": writes (or refreshes) the TraceBrake MCP entry — with a fresh scoped token —
    // for every agent TraceBrake sees running, that's already configured here, or that's installed on disk. This both
    // connects not-yet-wired agents AND repairs stale tokens on the configured ones (robust against a rotated
    // install secret, which silently 401s every saved token), in a single pass. Agents that are none of
    // running/configured/installed are left untouched, so TraceBrake never litters config for tools you don't use.
    // Logged via the bus so it lands in the event log / OS event log. TraceBrake writes the config; each agent opens
    // the MCP session on its NEXT start/restart — there's no way to force a running client to dial in.
    private void ConnectAllClick(object sender, RoutedEventArgs e)
    {
        var running = _getRunningHarnessIds?.Invoke();
        var results = HarnessConnectors.ConnectDetectedAndInstalled(_port, _mint, running);
        if (results.Count == 0)
        {
            MessageBox.Show(
                "No running, configured, or installed agents were found to connect. Connect one using a card below.",
                "TraceBrake — Connect all agents", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var ok = results.Where(r => r.Status != ConnectStatus.Failed).ToArray();
        var failed = results.Where(r => r.Status == ConnectStatus.Failed).ToArray();

        EventBus.Instance.Publish(new InfoEvent(
            DateTimeOffset.UtcNow,
            "Connect.All",
            $"Connect-all wrote TraceBrake MCP config for {ok.Length}/{results.Count} agent(s): {string.Join(", ", results.Select(r => r.HarnessId))}."));

        var msg = (ok.Length > 0
                ? $"Wrote TraceBrake config for: {string.Join(", ", ok.Select(r => r.DisplayName))}.\n\n" +
                  "Restart those agents (or refresh their MCP server) to connect — TraceBrake can't open the session for them."
                : "")
            + (failed.Length > 0
                ? $"\n\nCouldn't update: {string.Join("; ", failed.Select(f => $"{f.DisplayName} ({f.Message})"))}"
                : "");
        MessageBox.Show(msg.Trim(),
            "TraceBrake — Connect all agents",
            MessageBoxButton.OK,
            failed.Length > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        RefreshConnected();
    }

    /// <summary>Re-read the connected-agent list + CU driver state; called on tab-show.</summary>
    public void RefreshState()
    {
        RefreshConnected();
        RefreshCuDriver();
    }
}
