using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect OpenCode to TraceBrake": writes a <c>foreman</c> entry into OpenCode's
/// global <c>opencode.json</c> under its <c>mcp</c> object as a remote (streamable-HTTP) server with an
/// Authorization header. The whole file is parsed and rewritten via <see cref="JsonNode"/> so every other
/// setting is preserved; the original is backed up first.
///
/// Detection-first path: writes to whichever candidate <c>opencode.json</c> already exists (so it lands
/// where OpenCode actually reads), else creates the documented <c>~/.config/opencode/opencode.json</c>.
/// </summary>
public static class OpenCodeMcpConnector
{
    public static string Url(int port) => $"http://localhost:{port}/mcp";

    /// <summary>Global config locations OpenCode reads, most-preferred first (XDG, then ~/.config, then %APPDATA%).</summary>
    public static IEnumerable<string> CandidatePaths()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME");
        if (!string.IsNullOrWhiteSpace(xdg))
            yield return Path.Combine(xdg, "opencode", "opencode.json");
        yield return Path.Combine(home, ".config", "opencode", "opencode.json");
        var appData = Environment.GetEnvironmentVariable("APPDATA");
        if (!string.IsNullOrWhiteSpace(appData))
            yield return Path.Combine(appData, "opencode", "opencode.json");
    }

    public static string DefaultConfigPath =>
        CandidatePaths().FirstOrDefault(File.Exists)   // write where OpenCode already reads, if a config exists
        ?? CandidatePaths().First();                    // else the documented ~/.config default (will be created)

    private static JsonObject ServerObject(int port, string token) => new()
    {
        ["type"]    = "remote",
        ["url"]     = Url(port),
        ["enabled"] = true,
        ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
    };

    private static readonly JsonSerializerOptions _pretty = new() { WriteIndented = true };
    private static readonly JsonDocumentOptions _lenient =
        new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>The full opencode.json wrapper to paste (merge into the top-level mcp object).</summary>
    public static string BuildConfigSnippet(int port, string token) => new JsonObject
    {
        ["$schema"] = "https://opencode.ai/config.json",
        ["mcp"]     = new JsonObject { ["foreman"] = ServerObject(port, token) },
    }.ToJsonString(_pretty);

    /// <summary>True if opencode.json already has an mcp.foreman entry for this port with a token.</summary>
    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;
            var entry = (JsonNode.Parse(File.ReadAllText(path), documentOptions: _lenient) as JsonObject)?["mcp"]?["foreman"];
            if (entry is null) return false;
            var url  = entry["url"]?.GetValue<string>();
            var auth = entry["headers"]?["Authorization"]?.GetValue<string>();
            return string.Equals(url, Url(port), StringComparison.OrdinalIgnoreCase)
                   && !string.IsNullOrWhiteSpace(auth);
        }
        catch { return false; }
    }

    /// <summary>
    /// Adds or updates the foreman MCP entry under opencode.json's mcp object, preserving all other
    /// settings (and the $schema). Backs up the original first. Never throws.
    /// </summary>
    public static ConnectResult Connect(int port, string token, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            string original = File.Exists(path) ? File.ReadAllText(path) : "";
            var root = (original.Length > 0 ? JsonNode.Parse(original, documentOptions: _lenient) : new JsonObject()) as JsonObject
                       ?? throw new InvalidOperationException("opencode.json root is not a JSON object.");

            if (root["$schema"] is null)
                root["$schema"] = "https://opencode.ai/config.json";

            if (root["mcp"] is not JsonObject mcp)
            {
                mcp = new JsonObject();
                root["mcp"] = mcp;
            }

            var existed = mcp["foreman"] is not null;
            mcp["foreman"] = ServerObject(port, token);

            string? backup = null;
            if (original.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllText(backup, original);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, root.ToJsonString(_pretty));

            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                existed
                    ? $"Updated the foreman MCP entry in OpenCode's config ({path})."
                    : $"Added a foreman MCP entry to OpenCode's config ({path}).",
                backup);
        }
        catch (Exception ex)
        {
            return new ConnectResult(ConnectStatus.Failed, ex.Message);
        }
    }
}
