namespace Foreman.Core.Models;

public sealed record HarnessIntegration(
    string HarnessId,
    string DisplayName,
    string DefaultProfileName,
    string[] TrustedHookPathMarkers,
    string[] LauncherSuppressedRuleIds,
    string SetupHint,
    string McpConfigSnippet);

public static class HarnessIntegrationRegistry
{
    public static readonly IReadOnlyList<HarnessIntegration> All =
    [
        new(
            "claude-code",
            "Claude Code",
            "claude-code-default",
            [@".claude\hooks\", ".claude/hooks/"],
            ["win-002"],
            "Run: claude mcp add --transport http foreman http://localhost:{port}/mcp --header \"Authorization: Bearer <token>\" --scope user",
            """
            {
              "mcpServers": {
                "foreman": {
                  "type": "http",
                  "url": "http://localhost:{port}/mcp",
                  "headers": { "Authorization": "Bearer <token>" }
                }
              }
            }
            """),
        new(
            "codex",
            "Codex",
            "codex-default",
            [],
            [],
            "Add TraceBrake's HTTP MCP endpoint to ~/.codex/config.toml and the TraceBrake MCP Monitor section to ~/.codex/AGENTS.md, or use TraceBrake's Connect Agent window to write both automatically. Codex (CLI and Desktop) sends the bearer token from the FOREMAN_MCP_TOKEN_CODEX environment variable — set it to the token, then start Codex fresh (a new terminal, or relaunch the Desktop app). An inline http_headers Authorization is NOT applied by Codex.",
            """
            [mcp_servers.foreman]
            url = "http://localhost:{port}/mcp"
            bearer_token_env_var = "FOREMAN_MCP_TOKEN_CODEX"
            enabled = true
            """),
        new(
            "t3-code",
            "T3 Code",
            "t3-code-default",
            [],
            [],
            "Add TraceBrake's MCP endpoint to the underlying agent configured in T3 Code; monitor T3 Code itself as the control plane.",
            """
            {
              "mcpServers": {
                "foreman": {
                  "type": "http",
                  "url": "http://localhost:{port}/mcp",
                  "headers": { "Authorization": "Bearer <token>" }
                }
              }
            }
            """),
        new(
            "opencode",
            "OpenCode",
            "opencode-default",
            [@".opencode\hooks\", ".opencode/hooks/"],
            [],
            "Add TraceBrake's HTTP MCP endpoint to opencode.json under the mcp object.",
            """
            {
              "$schema": "https://opencode.ai/config.json",
              "mcp": {
                "foreman": {
                  "type": "remote",
                  "url": "http://localhost:{port}/mcp",
                  "enabled": true,
                  "headers": {
                    "Authorization": "Bearer <token>"
                  }
                }
              }
            }
            """),
        new(
            "gemini-cli",
            "Gemini CLI",
            "gemini-cli-default",
            [@".gemini\", ".gemini/"],
            [],
            "Add TraceBrake's MCP endpoint to ~/.gemini/settings.json under mcpServers — note Gemini uses httpUrl (streamable HTTP), not url. Use TraceBrake's Connect Agent window to write it automatically.",
            """
            {
              "mcpServers": {
                "foreman": {
                  "httpUrl": "http://localhost:{port}/mcp",
                  "headers": { "Authorization": "Bearer <token>" }
                }
              }
            }
            """),
        new(
            "github-copilot",
            "GitHub Copilot CLI",
            "github-copilot-default",
            [@".copilot\", ".copilot/"],
            [],
            "Add TraceBrake's HTTP MCP endpoint to ~/.copilot/mcp-config.json under mcpServers. Use TraceBrake's Connect Agent window to write it automatically. (The terminal 'copilot' CLI — not the Windows/Edge Microsoft Copilot.)",
            """
            {
              "mcpServers": {
                "foreman": {
                  "type": "http",
                  "url": "http://localhost:{port}/mcp",
                  "headers": { "Authorization": "Bearer <token>" },
                  "tools": ["*"]
                }
              }
            }
            """),
        new(
            "cursor",
            "Cursor",
            "cursor-default",
            [],
            [],
            "Add TraceBrake's MCP endpoint to ~/.cursor/mcp.json under mcpServers (a remote server — identified by 'url', with NO 'type' field). Use TraceBrake's Connect Agent window to write it automatically, then restart Cursor or refresh the foreman server in Settings -> Tools & MCP.",
            """
            {
              "mcpServers": {
                "foreman": {
                  "url": "http://localhost:{port}/mcp",
                  "headers": { "Authorization": "Bearer <token>" }
                }
              }
            }
            """),
        new(
            "lm-studio",
            "LM Studio",
            "lm-studio-default",
            [],
            [],
            "Add TraceBrake's MCP endpoint to ~/.lmstudio/mcp.json under mcpServers. Caveat emptor: LM Studio's support for a headers (Authorization) block on a remote server is unverified — confirm in LM Studio's MCP panel that the connection authorizes.",
            """
            {
              "mcpServers": {
                "foreman": {
                  "url": "http://localhost:{port}/mcp",
                  "headers": { "Authorization": "Bearer <token>" }
                }
              }
            }
            """),
    ];

    public static HarnessIntegration? Get(string harnessId) =>
        All.FirstOrDefault(h => string.Equals(h.HarnessId, harnessId, StringComparison.OrdinalIgnoreCase));

    public static string? GetDefaultProfileName(string harnessId) =>
        Get(harnessId)?.DefaultProfileName;

    public static KnownHarness? GetKnownHarness(string harnessId) =>
        KnownHarnesses.GetById(harnessId);
}
