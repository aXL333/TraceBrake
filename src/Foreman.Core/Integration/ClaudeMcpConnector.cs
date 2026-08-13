using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Integration;

public enum ConnectStatus { Added, Updated, Failed }

public sealed record ConnectResult(ConnectStatus Status, string Message, string? BackupPath = null);

/// <summary>
/// One-click "connect Claude Code to TraceBrake": writes a user-scope <c>foreman</c> MCP server entry
/// into Claude Code's config (<c>~/.claude.json</c>), so the user never has to hand-edit JSON or copy
/// a token. Mirrors exactly what <c>claude mcp add --scope user</c> does — a top-level
/// <c>mcpServers.foreman</c> with the streamable-HTTP url and an <c>Authorization: Bearer</c> header —
/// but without depending on the <c>claude</c> CLI being on PATH.
///
/// The whole config is parsed and rewritten via <see cref="JsonNode"/> so every other setting is
/// preserved, and the original is backed up first. Pure file/JSON logic, unit-tested.
/// </summary>
public static class ClaudeMcpConnector
{
    public static string DefaultConfigPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude.json");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    /// <summary>The equivalent CLI one-liner, for users who'd rather run it themselves.</summary>
    public static string BuildCliCommand(int port, string token) =>
        $"claude mcp add --transport http foreman {Url(port)} " +
        $"--header \"Authorization: Bearer {token}\" --scope user";

    private static JsonObject ServerObject(int port, string token) => new()
    {
        ["type"]    = "http",
        ["url"]     = Url(port),
        ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
    };

    private static readonly JsonSerializerOptions _pretty = new() { WriteIndented = true };

    /// <summary>The full mcpServers wrapper to paste into ~/.claude.json (Claude Code).</summary>
    public static string BuildClaudeConfigSnippet(int port, string token) =>
        new JsonObject { ["mcpServers"] = new JsonObject { ["foreman"] = ServerObject(port, token) } }
            .ToJsonString(_pretty);

    /// <summary>Just the foreman server entry, for clients that take a single server object.</summary>
    public static string BuildServerEntrySnippet(int port, string token) =>
        ServerObject(port, token).ToJsonString(_pretty);

    /// <summary>True if ~/.claude.json already has a top-level foreman entry for this port with a token.</summary>
    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;
            var entry = (JsonNode.Parse(File.ReadAllText(path)) as JsonObject)?["mcpServers"]?["foreman"];
            if (entry is null) return false;
            var url  = entry["url"]?.GetValue<string>();
            var auth = entry["headers"]?["Authorization"]?.GetValue<string>();
            return string.Equals(url, Url(port), StringComparison.OrdinalIgnoreCase)
                   && !string.IsNullOrWhiteSpace(auth);
        }
        catch { return false; }
    }

    /// <summary>
    /// Adds or updates the user-scope foreman MCP entry. Backs up the existing config first.
    /// Never throws — failures come back as <see cref="ConnectStatus.Failed"/> with a message.
    /// </summary>
    public static ConnectResult Connect(int port, string token, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            string original = File.Exists(path) ? File.ReadAllText(path) : "";
            var root = (original.Length > 0 ? JsonNode.Parse(original) : new JsonObject()) as JsonObject
                       ?? throw new InvalidOperationException("Claude config root is not a JSON object.");

            if (root["mcpServers"] is not JsonObject servers)
            {
                servers = new JsonObject();
                root["mcpServers"] = servers;
            }

            var existed = servers["foreman"] is not null;
            servers["foreman"] = new JsonObject
            {
                ["type"]    = "http",
                ["url"]     = Url(port),
                ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
            };

            string? backup = null;
            if (original.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllText(backup, original);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                existed
                    ? "Updated the existing foreman MCP entry in Claude Code's config."
                    : "Added a user-scope foreman MCP entry to Claude Code's config.",
                backup);
        }
        catch (Exception ex)
        {
            return new ConnectResult(ConnectStatus.Failed, ex.Message);
        }
    }
}
