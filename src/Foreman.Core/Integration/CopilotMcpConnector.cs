using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect GitHub Copilot CLI to TraceBrake": writes a <c>foreman</c> entry into
/// Copilot CLI's global <c>~/.copilot/mcp-config.json</c> under <c>mcpServers</c> as a remote HTTP server
/// (<c>type: "http"</c> + <c>url</c> + an <c>Authorization: Bearer</c> header, with <c>tools: ["*"]</c> so
/// every TraceBrake tool is available).
///
/// The file is parsed and rewritten via <see cref="JsonNode"/> so every other server is preserved, the
/// original is backed up first, and the swap is atomic (temp + replace). Path/format were confirmed against
/// the current GitHub Copilot CLI docs ("Adding MCP servers for GitHub Copilot CLI") before this was written.
/// </summary>
public static class CopilotMcpConnector
{
    public static string DefaultConfigPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".copilot", "mcp-config.json");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    private static JsonObject ServerObject(int port, string token) => new()
    {
        ["type"]    = "http",
        ["url"]     = Url(port),
        ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
        ["tools"]   = new JsonArray("*"),
    };

    private static readonly JsonSerializerOptions _pretty = new() { WriteIndented = true };
    private static readonly JsonDocumentOptions _lenient =
        new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>The full mcpServers wrapper to paste into ~/.copilot/mcp-config.json.</summary>
    public static string BuildConfigSnippet(int port, string token) =>
        new JsonObject { ["mcpServers"] = new JsonObject { ["foreman"] = ServerObject(port, token) } }
            .ToJsonString(_pretty);

    /// <summary>True if mcp-config.json already has an mcpServers.foreman HTTP entry for this port with a token.</summary>
    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;
            var entry = (JsonNode.Parse(File.ReadAllText(path), documentOptions: _lenient) as JsonObject)?["mcpServers"]?["foreman"];
            if (entry is null) return false;
            var url  = entry["url"]?.GetValue<string>();
            var auth = entry["headers"]?["Authorization"]?.GetValue<string>();
            return string.Equals(url, Url(port), StringComparison.OrdinalIgnoreCase)
                   && !string.IsNullOrWhiteSpace(auth);
        }
        catch { return false; }
    }

    /// <summary>
    /// Adds or updates the foreman remote server under mcpServers, preserving every other entry. Backs up
    /// the original and swaps atomically. A malformed existing file fails safely (returns Failed; the user
    /// can copy-paste) rather than being clobbered.
    /// </summary>
    public static ConnectResult Connect(int port, string token, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            string original = File.Exists(path) ? File.ReadAllText(path) : "";
            var root = (original.Length > 0 ? JsonNode.Parse(original, documentOptions: _lenient) : new JsonObject()) as JsonObject
                       ?? throw new InvalidOperationException("~/.copilot/mcp-config.json root is not a JSON object.");

            if (root["mcpServers"] is not JsonObject servers)
            {
                servers = new JsonObject();
                root["mcpServers"] = servers;
            }

            var existed = servers["foreman"] is not null;
            servers["foreman"] = ServerObject(port, token);

            string? backup = null;
            if (original.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllText(backup, original);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            AtomicWrite(path, root.ToJsonString(_pretty));

            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                existed
                    ? "Updated the foreman MCP entry in GitHub Copilot CLI's config (~/.copilot/mcp-config.json)."
                    : "Added a foreman MCP entry to GitHub Copilot CLI's config (~/.copilot/mcp-config.json).",
                backup);
        }
        catch (Exception ex)
        {
            return new ConnectResult(ConnectStatus.Failed, ex.Message);
        }
    }

    private static void AtomicWrite(string path, string contents)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, contents);
        try
        {
            if (File.Exists(path)) File.Replace(tmp, path, destinationBackupFileName: null);
            else File.Move(tmp, path);
        }
        catch
        {
            File.Copy(tmp, path, overwrite: true);   // AV/indexer lock fallback
            try { File.Delete(tmp); } catch { }
        }
    }
}
