using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect Gemini CLI to TraceBrake": writes a <c>foreman</c> entry into Gemini CLI's
/// global <c>~/.gemini/settings.json</c> under <c>mcpServers</c> as a streamable-HTTP server.
///
/// IMPORTANT: Gemini CLI distinguishes transports by field name — <c>httpUrl</c> is streamable HTTP, while
/// <c>url</c> is SSE. TraceBrake serves streamable HTTP, so the entry uses <c>httpUrl</c> (NOT <c>url</c>) plus a
/// <c>headers</c> object carrying the <c>Authorization: Bearer</c> token.
///
/// settings.json is the user's MAIN config, so the whole file is parsed and rewritten via <see cref="JsonNode"/>
/// to preserve every other setting; the original is backed up first and the swap is atomic. Parsing is lenient
/// (comments/trailing commas tolerated); the rewrite is strict JSON. Format/path confirmed against the current
/// Gemini CLI MCP docs before this was written.
/// </summary>
public static class GeminiMcpConnector
{
    public static string DefaultConfigPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".gemini", "settings.json");

    public static string HttpUrl(int port) => $"http://localhost:{port}/mcp";

    private static JsonObject ServerObject(int port, string token) => new()
    {
        ["httpUrl"] = HttpUrl(port),
        ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
    };

    private static readonly JsonSerializerOptions _pretty = new() { WriteIndented = true };
    private static readonly JsonDocumentOptions _lenient =
        new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>The full mcpServers wrapper to paste into ~/.gemini/settings.json (merge into mcpServers).</summary>
    public static string BuildConfigSnippet(int port, string token) =>
        new JsonObject { ["mcpServers"] = new JsonObject { ["foreman"] = ServerObject(port, token) } }
            .ToJsonString(_pretty);

    /// <summary>True if settings.json already has an mcpServers.foreman streamable-HTTP entry for this port with a token.</summary>
    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;
            var entry = (JsonNode.Parse(File.ReadAllText(path), documentOptions: _lenient) as JsonObject)?["mcpServers"]?["foreman"];
            if (entry is null) return false;
            var url  = entry["httpUrl"]?.GetValue<string>();
            var auth = entry["headers"]?["Authorization"]?.GetValue<string>();
            return string.Equals(url, HttpUrl(port), StringComparison.OrdinalIgnoreCase)
                   && !string.IsNullOrWhiteSpace(auth);
        }
        catch { return false; }
    }

    /// <summary>
    /// Adds or updates the foreman server under mcpServers, preserving every other setting in settings.json.
    /// Backs up the original and swaps atomically. A malformed existing file fails safely (returns Failed;
    /// the user can copy-paste) rather than being clobbered.
    /// </summary>
    public static ConnectResult Connect(int port, string token, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            string original = File.Exists(path) ? File.ReadAllText(path) : "";
            var root = (original.Length > 0 ? JsonNode.Parse(original, documentOptions: _lenient) : new JsonObject()) as JsonObject
                       ?? throw new InvalidOperationException("~/.gemini/settings.json root is not a JSON object.");

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
                    ? "Updated the foreman MCP entry in Gemini CLI's config (~/.gemini/settings.json)."
                    : "Added a foreman MCP entry to Gemini CLI's config (~/.gemini/settings.json).",
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
