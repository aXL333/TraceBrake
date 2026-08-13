using System.Text.Json;
using System.Text.Json.Nodes;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect LM Studio to TraceBrake": writes a <c>foreman</c> entry into LM Studio's
/// <c>~/.lmstudio/mcp.json</c> under <c>mcpServers</c>.
///
/// LM Studio has a confirmed bug (lmstudio-ai/lmstudio-bug-tracker#1892) where it does NOT forward the
/// <c>Authorization</c> header to REMOTE MCP servers, so a direct <c>{ url, headers }</c> entry reaches TraceBrake's
/// token-gated <c>/mcp</c> unauthenticated and is rejected (LM Studio then falls back to OAuth, which Foreman
/// does not implement). The DEFAULT shape is therefore a LOCAL stdio bridge: LM Studio launches
/// <c>mcp-remote</c> (a small, widely-used stdio-to-HTTP MCP proxy) which injects the bearer header itself and
/// forwards to TraceBrake's loopback endpoint. Local stdio servers are not affected by #1892, so this works today.
/// The bearer value is passed via an <c>AUTH</c> env var and referenced as <c>--header "Authorization:${AUTH}"</c>
/// (mcp-remote's documented form for header values containing a space).
///
/// TRADE-OFF: the bridge needs Node/<c>npx</c> on PATH and pulls <c>mcp-remote</c> from npm on first run (a
/// third-party dependency - flagged plainly, since TraceBrake otherwise warns about npx-fetched packages). Pass
/// <paramref name="useHeaderBridge"/> = false to emit the plain remote <c>{ url, headers }</c> form instead (the
/// spec-correct shape that will work once LM Studio fixes #1892, and the right choice if you don't want npx).
/// Everything else (atomic write, backup, fail-safe parse) is hardened the same as the other connectors.
/// </summary>
public static class LmStudioMcpConnector
{
    public static string DefaultConfigPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".lmstudio", "mcp.json");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    // Plain remote form: spec-correct, but LM Studio #1892 drops the header today.
    private static JsonObject RemoteServerObject(int port, string token) => new()
    {
        ["url"]     = Url(port),
        ["headers"] = new JsonObject { ["Authorization"] = $"Bearer {token}" },
    };

    // Local stdio bridge (default): mcp-remote injects the header and proxies to the loopback endpoint, sidestepping
    // #1892. Token rides an env var; "Authorization:${AUTH}" is mcp-remote's documented way to send a value with a space.
    private static JsonObject BridgeServerObject(int port, string token) => new()
    {
        ["command"] = "npx",
        ["args"]    = new JsonArray("-y", "mcp-remote", Url(port), "--header", "Authorization:${AUTH}"),
        ["env"]     = new JsonObject { ["AUTH"] = $"Bearer {token}" },
    };

    private static JsonObject ServerObject(int port, string token, bool useHeaderBridge) =>
        useHeaderBridge ? BridgeServerObject(port, token) : RemoteServerObject(port, token);

    private static readonly JsonSerializerOptions _pretty = new() { WriteIndented = true };
    private static readonly JsonDocumentOptions _lenient =
        new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>The full mcpServers wrapper to paste into ~/.lmstudio/mcp.json (merge into mcpServers).</summary>
    public static string BuildConfigSnippet(int port, string token, bool useHeaderBridge = true) =>
        new JsonObject { ["mcpServers"] = new JsonObject { ["foreman"] = ServerObject(port, token, useHeaderBridge) } }
            .ToJsonString(_pretty);

    /// <summary>True if mcp.json already has a foreman entry for this port - either the bridge form (npx mcp-remote
    /// pointed at this port) or the remote form (url + an Authorization header).</summary>
    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;
            var entry = (JsonNode.Parse(File.ReadAllText(path), documentOptions: _lenient) as JsonObject)?["mcpServers"]?["foreman"];
            if (entry is null) return false;

            // Remote form: url for this port + a non-empty Authorization header.
            var url  = entry["url"]?.GetValue<string>();
            var auth = entry["headers"]?["Authorization"]?.GetValue<string>();
            if (string.Equals(url, Url(port), StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(auth))
                return true;

            // Bridge form: a command server whose args reference mcp-remote and this port's loopback url.
            if (entry["args"] is JsonArray args)
            {
                var hasRemote = args.Any(a => string.Equals(a?.GetValue<string>(), "mcp-remote", StringComparison.OrdinalIgnoreCase));
                var hasUrl    = args.Any(a => string.Equals(a?.GetValue<string>(), Url(port), StringComparison.OrdinalIgnoreCase));
                if (hasRemote && hasUrl) return true;
            }
            return false;
        }
        catch { return false; }
    }

    /// <summary>
    /// Adds or updates the foreman server under mcpServers, preserving every other entry. Defaults to the stdio
    /// bridge (works around LM Studio #1892); pass <paramref name="useHeaderBridge"/> = false for the plain remote
    /// form. Backs up the original and swaps atomically. A malformed existing file fails safely (returns Failed;
    /// the user can copy-paste) rather than being clobbered.
    /// </summary>
    public static ConnectResult Connect(int port, string token, bool useHeaderBridge = true, string? configPath = null)
    {
        var path = configPath ?? DefaultConfigPath;
        try
        {
            string original = File.Exists(path) ? File.ReadAllText(path) : "";
            var root = (original.Length > 0 ? JsonNode.Parse(original, documentOptions: _lenient) : new JsonObject()) as JsonObject
                       ?? throw new InvalidOperationException("~/.lmstudio/mcp.json root is not a JSON object.");

            if (root["mcpServers"] is not JsonObject servers)
            {
                servers = new JsonObject();
                root["mcpServers"] = servers;
            }

            var existed = servers["foreman"] is not null;
            servers["foreman"] = ServerObject(port, token, useHeaderBridge);

            string? backup = null;
            if (original.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllText(backup, original);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            AtomicWrite(path, root.ToJsonString(_pretty));

            var how = useHeaderBridge
                ? " (via a local mcp-remote bridge - needs Node/npx, works around LM Studio bug #1892)"
                : "";
            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                (existed
                    ? "Updated the foreman MCP entry in LM Studio's config (~/.lmstudio/mcp.json)"
                    : "Added a foreman MCP entry to LM Studio's config (~/.lmstudio/mcp.json)") + how + ".",
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
