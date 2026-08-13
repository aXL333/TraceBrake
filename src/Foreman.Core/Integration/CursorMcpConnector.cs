using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect Cursor to TraceBrake": writes a <c>foreman</c> entry into Cursor's global
/// <c>~/.cursor/mcp.json</c> under <c>mcpServers</c> as a remote server (a <c>url</c> + an
/// <c>Authorization: Bearer</c> header — Cursor identifies a remote server by the presence of <c>url</c>;
/// there is deliberately NO <c>type</c> field, which the docs reserve for local stdio servers).
///
/// The file is parsed as STRICT JSON and rewritten via <see cref="JsonNode"/> so every other server/setting
/// is preserved, the original is backed up first, and the swap is atomic (temp + replace). Format/path were
/// confirmed against the current Cursor docs before this was written.
/// </summary>
public static class CursorMcpConnector
{
    public static string DefaultConfigPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cursor", "mcp.json");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    private static JsonObject ServerObject(int port, string token) => new()
    {
        ["url"]     = Url(port),
        ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
    };

    private static readonly JsonSerializerOptions _pretty = new() { WriteIndented = true };

    /// <summary>The full mcpServers wrapper to paste into ~/.cursor/mcp.json (merge into the mcpServers object).</summary>
    public static string BuildConfigSnippet(int port, string token) =>
        new JsonObject { ["mcpServers"] = new JsonObject { ["foreman"] = ServerObject(port, token) } }
            .ToJsonString(_pretty);

    /// <summary>True if ~/.cursor/mcp.json already has an mcpServers.foreman remote entry for this port with a token.</summary>
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
    /// Adds or updates the foreman remote server under mcpServers, preserving every other entry. Backs up
    /// the original and swaps atomically. mcp.json is strict JSON (no comments/trailing commas) — a malformed
    /// existing file fails safely (returns Failed; the user can copy-paste) rather than being clobbered.
    /// </summary>
    public static ConnectResult Connect(int port, string token, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            string original = File.Exists(path) ? File.ReadAllText(path) : "";
            var root = (original.Length > 0 ? JsonNode.Parse(original) : new JsonObject()) as JsonObject
                       ?? throw new InvalidOperationException("~/.cursor/mcp.json root is not a JSON object.");

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
                    ? "Updated the foreman MCP entry in Cursor's config (~/.cursor/mcp.json)."
                    : "Added a foreman MCP entry to Cursor's config (~/.cursor/mcp.json).",
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
