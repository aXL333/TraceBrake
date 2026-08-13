using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Foreman.McpServer;

/// <summary>Outcome of authenticating a presented MCP bearer token.</summary>
public readonly record struct McpAuthResult(bool Ok, string? HarnessId, bool IsOperator)
{
    public static readonly McpAuthResult Fail = new(false, null, false);
    public static readonly McpAuthResult Operator = new(true, null, true);
}

/// <summary>
/// A stable, per-install bearer token that gates the MCP HTTP endpoint.
///
/// The MCP server binds to localhost, but "localhost" is not an authorization boundary on a
/// shared machine - any process or a browser via a forged request can reach it. Requiring a
/// secret token means a caller must be able to read the token file under the user's profile,
/// which a browser cannot do and a drive-by request cannot guess. It does not and cannot stop
/// a process already running as the same user from reading the file. That is the OS trust
/// boundary, documented in the setup file, but it closes the "anyone on loopback" hole.
///
/// The token is generated once and persisted, so a harness's MCP config can reference it
/// statically; it is regenerated only if the file is missing or empty.
/// </summary>
public sealed class McpAuthToken
{
    private readonly string _tokenPath;
    private readonly string _setupPath;

    public string Value { get; }

    /// <summary>Absolute path of the token file, so the host can harden its ACL on Windows.</summary>
    public string TokenFilePath => _tokenPath;

    /// <summary>
    /// LastWriteTime (UTC) of the persisted token file, or null when it does not exist or can't be read.
    /// LoadOrCreate regenerates the file ONLY when it is missing/empty, so a recent write time is the only
    /// honest signal that the install secret was actually rotated.
    /// </summary>
    public DateTimeOffset? TokenFileWriteTimeUtc
    {
        get
        {
            try { return File.Exists(_tokenPath) ? new DateTimeOffset(File.GetLastWriteTimeUtc(_tokenPath)) : null; }
            catch { return null; }
        }
    }

    // A token file (re)written within this window of now reads as a recent regeneration -> the install
    // secret was plausibly rotated. Outside it, the file is old, so rotation is NOT a safe claim.
    private static readonly TimeSpan RegenRecencyWindow = TimeSpan.FromHours(1);

    /// <summary>True if the token file was (re)written within the default recency window, i.e. the install
    /// secret was plausibly rotated recently. False when the file is old (the common case) or its time can't
    /// be read.</summary>
    public bool RecentlyRegenerated() => RecentlyRegenerated(RegenRecencyWindow);

    /// <summary>True if the token file was (re)written within <paramref name="window"/> of now.</summary>
    public bool RecentlyRegenerated(TimeSpan window) =>
        TokenFileWriteTimeUtc is { } when && DateTimeOffset.UtcNow - when < window;

    public McpAuthToken(string? baseDirectory = null)
    {
        var dir = baseDirectory ?? Foreman.Core.ProductIdentity.LocalDataRoot;
        _tokenPath = Path.Combine(dir, "mcp.token");
        _setupPath = Path.Combine(dir, "mcp-setup.txt");
        Value = LoadOrCreate(dir, _tokenPath);
    }

    private static string LoadOrCreate(string dir, string tokenPath)
    {
        try
        {
            if (File.Exists(tokenPath))
            {
                var existing = File.ReadAllText(tokenPath).Trim();
                if (existing.Length >= 32) return existing;
            }
        }
        catch { /* unreadable - fall through and mint a fresh one */ }

        var token = Generate();
        try
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(tokenPath, token);
        }
        catch { /* can't persist - token still works for this run, just not reusable */ }
        return token;
    }

    private static string Generate()
    {
        // 32 random bytes, URL-safe base64, no padding.
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>True if a presented token is valid (operator OR a per-harness token). Back-compat shim.</summary>
    public bool Matches(string? presented) => Authenticate(presented).Ok;

    private const string HarnessTokenPrefix = "fmh1.";

    /// <summary>
    /// Mints a per-harness bearer token <c>fmh1.&lt;base64url(harnessId)&gt;.&lt;mac&gt;</c>, where mac =
    /// HMAC-SHA256(install-secret, harnessId). Stateless: the identity is carried in the token and the
    /// MAC proves TraceBrake minted it — so a connected agent's identity is unforgeable without the
    /// (user-ACL'd) install secret, and no per-harness secret has to be stored.
    /// </summary>
    public string MintHarnessToken(string harnessId)
    {
        // Normalize to lower-case so the id carried in the token matches the MAC (computed over the
        // lower-cased id) and the harness ids used everywhere else (claude-code, codex, custom:foo.exe).
        var id = (harnessId ?? string.Empty).Trim().ToLowerInvariant();
        var idB64 = Base64Url(Encoding.UTF8.GetBytes(id));
        return $"{HarnessTokenPrefix}{idB64}.{ComputeMac(Value, id)}";
    }

    /// <summary>
    /// Authenticates a presented bearer token. The raw install token authenticates as the unscoped
    /// OPERATOR (back-compat: existing single-token agent configs keep full access). A valid per-harness
    /// token authenticates as that harness (scoped). Anything else fails.
    /// </summary>
    public McpAuthResult Authenticate(string? presented)
    {
        if (string.IsNullOrEmpty(presented)) return McpAuthResult.Fail;

        // Operator: raw install secret (in-memory or current on-disk — stale-instance safe).
        if (FixedEquals(presented, Value) || FixedEquals(presented, ReadPersistedToken()))
            return McpAuthResult.Operator;

        // Per-harness: fmh1.<b64(harnessId)>.<mac>
        if (presented.StartsWith(HarnessTokenPrefix, StringComparison.Ordinal))
        {
            var parts = presented.Split('.');
            if (parts.Length == 3 && parts[0] == "fmh1")
            {
                string id;
                try { id = Encoding.UTF8.GetString(Base64UrlDecode(parts[1])); }
                catch { return McpAuthResult.Fail; }
                if (string.IsNullOrEmpty(id)) return McpAuthResult.Fail;

                var mac = parts[2];
                var disk = ReadPersistedToken();
                if (FixedEquals(mac, ComputeMac(Value, id)) ||
                    (disk is not null && FixedEquals(mac, ComputeMac(disk, id))))
                    return new McpAuthResult(true, id, false);
            }
        }
        return McpAuthResult.Fail;
    }

    /// <summary>
    /// True if a FAILED token is a structurally-valid per-harness token (<c>fmh1.&lt;b64(id)&gt;.&lt;mac&gt;</c>)
    /// whose id is a plausible harness id — i.e. it failed only because the MAC doesn't match the CURRENT install
    /// secret. The overwhelmingly common cause is secret rotation (the saved token went stale); the only other
    /// cause is a forged token. The id is UNVERIFIED (carried in the token, not proven by the MAC), so callers
    /// must treat it as a claim. Returns false for the operator token, missing/garbage tokens, or an implausible
    /// id — so a forged token can't inject arbitrary text into a log line.
    /// </summary>
    public bool LooksLikeStaleHarnessToken(string? presented, out string harnessId)
    {
        harnessId = "";
        if (string.IsNullOrEmpty(presented) || !presented.StartsWith(HarnessTokenPrefix, StringComparison.Ordinal))
            return false;
        if (Authenticate(presented).Ok) return false;   // a token that still validates isn't stale
        var parts = presented.Split('.');
        if (parts.Length != 3 || parts[0] != "fmh1") return false;
        string id;
        try { id = Encoding.UTF8.GetString(Base64UrlDecode(parts[1])); }
        catch { return false; }
        if (!IsPlausibleHarnessId(id)) return false;
        harnessId = id;
        return true;
    }

    // Harness ids are lowercase tokens like "codex", "claude-code", "lm-studio", "custom:foo.exe" (MintHarnessToken
    // lower-cases them). Bound the shape and length so a forged token can't inject arbitrary/oversized text into the
    // operator-facing stale-token notice.
    private static bool IsPlausibleHarnessId(string id) =>
        id.Length is > 0 and <= 64 &&
        id.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '-' or '_' or ':' or '.');

    private static string ComputeMac(string secret, string harnessId)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Base64Url(hmac.ComputeHash(Encoding.UTF8.GetBytes(harnessId.ToLowerInvariant())));
    }

    private static string Base64Url(byte[] b) =>
        Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] Base64UrlDecode(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        t += (t.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(t);
    }

    private string? ReadPersistedToken()
    {
        try
        {
            if (!File.Exists(_tokenPath)) return null;
            var token = File.ReadAllText(_tokenPath).Trim();
            return token.Length >= 32 ? token : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool FixedEquals(string presented, string? expected)
    {
        if (string.IsNullOrEmpty(expected)) return false;
        var a = Encoding.UTF8.GetBytes(presented);
        var b = Encoding.UTF8.GetBytes(expected);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    /// <summary>Writes a human-readable, ready-to-paste setup file next to the token.</summary>
    public void WriteSetupFile(int port)
    {
        var snippet =
$$"""
TraceBrake MCP - connection setup
===========================================

TraceBrake's MCP server requires a bearer token. It listens on:

    http://localhost:{{port}}/mcp        (tools - requires the token)
    http://localhost:{{port}}/health     (liveness - open)

Your token is in the file 'mcp.token' next to this file - it is readable only by you.
Add it as an Authorization header in your harness's MCP client config, replacing <TOKEN>
with the contents of mcp.token.

Claude Code JSON example:

{
  "mcpServers": {
    "foreman": {
      "type": "http",
      "url": "http://localhost:{{port}}/mcp",
      "headers": { "Authorization": "Bearer <TOKEN>" }
    }
  }
}

Codex TOML example:

[mcp_servers.foreman]
url = "http://localhost:{{port}}/mcp"
http_headers = { Authorization = "Bearer <TOKEN>" }
enabled = true

Keep mcp.token private - anyone who can read it can call TraceBrake's MCP tools.
Delete mcp.token to force a new token (you must then update every client config).
""";
        try { File.WriteAllText(_setupPath, snippet); }
        catch { /* best-effort */ }
    }
}
