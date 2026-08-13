using System.Text;
using System.Text.RegularExpressions;

namespace Foreman.Core.Integration;

/// <summary>
/// One-click "connect Codex to TraceBrake": writes TraceBrake's streamable-HTTP MCP
/// server into Codex's user config (<c>~/.codex/config.toml</c>) and adds a
/// bounded TraceBrake section to <c>~/.codex/AGENTS.md</c>.
///
/// Codex stores MCP servers as TOML tables under <c>[mcp_servers.&lt;name&gt;]</c>.
/// This helper only owns the <c>foreman</c> table, preserves unrelated config,
/// and backs up the original file before writing.
/// </summary>
public static class CodexMcpConnector
{
    private const string SectionName = "mcp_servers.foreman";
    private const string AgentsBeginMarker = "<!-- foreman-mcp:begin -->";
    private const string AgentsEndMarker = "<!-- foreman-mcp:end -->";

    /// <summary>
    /// Environment variable Codex reads the bearer token from. Codex's supported way to authenticate a
    /// streamable-HTTP MCP server is <c>bearer_token_env_var</c> (it sends the variable's value as
    /// <c>Authorization: Bearer …</c>). Codex 0.98 does NOT apply an inline <c>http_headers</c> Authorization
    /// for auth — it lists such a server as "Auth: Unsupported" and connects without the header — so the token
    /// is delivered via this variable instead.
    /// </summary>
    public const string BearerTokenEnvVar = "FOREMAN_MCP_TOKEN_CODEX";

    public static string DefaultConfigPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "config.toml");

    public static string DefaultAgentsPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".codex",
            "AGENTS.md");

    public static string Url(int port) => $"http://localhost:{port}/mcp";

    public static string BuildConfigSnippet(int port, string token) =>
        BuildSection(port).TrimEnd() + "\n\n" +
        "# Codex sends the bearer token from this environment variable. Set it, then start Codex in a NEW\n" +
        "# terminal (so it inherits the value):\n" +
        $"#   setx {BearerTokenEnvVar} \"{token}\"";

    public static string BuildAgentsInstructions() =>
        $"""
        {AgentsBeginMarker}
        ## TraceBrake MCP Monitor

        When the `foreman` MCP server is available:

        - Identify this agent as `harnessId: "codex"` when TraceBrake tools accept a harness id.
        - At the start of a new task, call `report_task_start(taskDescription, harnessId: "codex")`.
        - At task boundaries, or when your context window drops (e.g. below ~50%), call `report_usage(percentRemaining: <0-100>, harnessId: "codex")` so the operator can see your remaining context on the dashboard.
        - If `foreman_status` or `report_task_start` reports `pendingAskHarnessRequests`, call `list_ask_harness_requests(harnessId: "codex")`.
        - For each pending request addressed to Codex (Ask Harness or queued audit prompt), answer with `reply_to_ask_harness_request(requestId, response, actionTaken, harnessId: "codex")`.
        - Treat each request as a safety prompt: explain what happened, whether it was expected, and any corrective action you took or recommend.

        {AgentsEndMarker}
        """;

    public static bool IsConfigured(int port, string? configPath = null)
    {
        try
        {
            var path = configPath ?? DefaultConfigPath;
            if (!File.Exists(path)) return false;

            var section = ExtractForemanSection(File.ReadAllText(path));
            if (section is null) return false;

            return HasAssignment(section, "url", Url(port)) &&
                   (HasInlineAuthorizationHeader(section) ||
                    Regex.IsMatch(section, @"(?im)^\s*bearer_token_env_var\s*=\s*""[^""]+""\s*(?:#.*)?$"));
        }
        catch
        {
            return false;
        }
    }

    public static ConnectResult Connect(
        int port,
        string token,
        string? configPath = null,
        string? agentsPath = null,
        Action<string, string>? setUserEnvVar = null)
    {
        var path = configPath ?? DefaultConfigPath;
        setUserEnvVar ??= SetUserEnvVar;
        try
        {
            var bytes = File.Exists(path) ? File.ReadAllBytes(path) : [];
            var hadBom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
            var original = bytes.Length == 0
                ? ""
                : new UTF8Encoding(false).GetString(hadBom ? bytes[3..] : bytes);

            // Respect a user who wired their OWN bearer_token_env_var (a variable name other than TraceBrake's)
            // for this port - don't clobber their setup or touch their variable.
            var existingSection = ExtractForemanSection(original);
            if (existingSection is not null &&
                HasAssignment(existingSection, "url", Url(port)) &&
                TryGetBearerTokenEnvVarName(existingSection, out var existingVar) &&
                !string.Equals(existingVar, BearerTokenEnvVar, StringComparison.Ordinal))
            {
                var secureEntryMessage =
                    $"Codex already has a foreman entry using your own bearer_token_env_var ({existingVar}) for " +
                    $"this port - left it unchanged. Set {existingVar} to TraceBrake's token to (re)connect.";

                return new ConnectResult(
                    ConnectStatus.Updated,
                    AppendAgentsNote(secureEntryMessage, agentsPath ?? DefaultAgentsPath),
                    null);
            }

            // Preserve the file's own newline + BOM so a one-click connect only changes the foreman table,
            // not the whole file's encoding (avoids noisy LF/CRLF or BOM diffs under git).
            var newline = original.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var updated = UpsertForemanSection(original, port, newline, out var existed);

            string? backup = null;
            if (bytes.Length > 0)
            {
                backup = path + ".foreman-bak";
                File.WriteAllBytes(backup, bytes);   // verbatim copy preserves the original's exact bytes
            }

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, updated, new UTF8Encoding(encoderShouldEmitUTF8Identifier: hadBom));

            // Deliver the token the only way Codex consumes it for an HTTP server: the environment variable
            // named by bearer_token_env_var. (Inline http_headers Authorization is ignored by Codex 0.98.)
            string envNote;
            try
            {
                setUserEnvVar(BearerTokenEnvVar, token);
                envNote = $" Set {BearerTokenEnvVar} for your user account - start Codex in a NEW terminal so it picks up the token.";
            }
            catch (Exception ex)
            {
                envNote = $" Couldn't set {BearerTokenEnvVar} automatically ({ex.Message}) - set it yourself: setx {BearerTokenEnvVar} \"<token>\".";
            }

            var message = (existed
                ? "Updated the existing foreman MCP entry in Codex's config."
                : "Added a user-scope foreman MCP entry to Codex's config.") + envNote;

            return new ConnectResult(
                existed ? ConnectStatus.Updated : ConnectStatus.Added,
                AppendAgentsNote(message, agentsPath ?? DefaultAgentsPath),
                backup);
        }
        catch (Exception ex)
        {
            return new ConnectResult(ConnectStatus.Failed, ex.Message);
        }
    }

    private static void SetUserEnvVar(string name, string value)
    {
        if (OperatingSystem.IsWindows())
            Environment.SetEnvironmentVariable(name, value, EnvironmentVariableTarget.User);
        else
            Environment.SetEnvironmentVariable(name, value);   // process-scope fallback off-Windows
    }

    private static string UpsertForemanSection(string original, int port, string newline, out bool existed)
    {
        var lines = NormalizeLines(original);
        if (lines.Count == 1 && lines[0].Length == 0)
            lines.Clear();

        var range = FindForemanSectionRange(lines);
        var section = BuildSection(port).TrimEnd().Split('\n');

        existed = range is not null;
        if (range is { } r)
        {
            lines.RemoveRange(r.Start, r.EndExclusive - r.Start);
            lines.InsertRange(r.Start, section);
        }
        else
        {
            if (lines.Count > 0 && !string.IsNullOrWhiteSpace(lines[^1]))
                lines.Add("");
            lines.AddRange(section);
        }

        return string.Join(newline, lines).TrimEnd() + newline;
    }

    private static string BuildSection(int port) =>
        $"[{SectionName}]\n" +
        $"url = \"{TomlEscape(Url(port))}\"\n" +
        $"bearer_token_env_var = \"{BearerTokenEnvVar}\"\n" +
        "enabled = true\n";

    private static string AppendAgentsNote(string message, string agentsPath)
    {
        TryUpsertAgentsInstructions(
            agentsPath,
            out var agentsBackup,
            out var agentsChanged,
            out var agentsError);

        if (agentsError is not null)
            return message + $" Codex config is ready, but TraceBrake couldn't update AGENTS.md: {agentsError}";

        if (!agentsChanged)
            return message + " TraceBrake's Codex instructions in AGENTS.md were already current.";

        message += " Added/updated TraceBrake's Codex instructions in AGENTS.md.";
        if (agentsBackup is not null)
            message += $" AGENTS backup saved: {agentsBackup}";
        return message;
    }

    private static bool TryUpsertAgentsInstructions(
        string agentsPath,
        out string? backupPath,
        out bool changed,
        out string? error)
    {
        backupPath = null;
        changed = false;
        error = null;

        try
        {
            var original = File.Exists(agentsPath) ? File.ReadAllText(agentsPath) : "";
            var newline = original.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
            var desired = BuildAgentsInstructions().Replace("\r\n", "\n").Replace("\n", newline).TrimEnd();
            var updated = UpsertMarkedBlock(original, desired, newline);

            if (string.Equals(original, updated, StringComparison.Ordinal))
                return true;

            if (original.Length > 0)
            {
                backupPath = agentsPath + ".foreman-bak";
                File.WriteAllText(backupPath, original, new UTF8Encoding(false));
            }

            Directory.CreateDirectory(Path.GetDirectoryName(agentsPath)!);
            File.WriteAllText(agentsPath, updated, new UTF8Encoding(false));
            changed = true;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string UpsertMarkedBlock(string original, string block, string newline)
    {
        var normalized = original.Replace("\r\n", "\n").Replace('\r', '\n');
        var normalizedBlock = block.Replace("\r\n", "\n").Replace('\r', '\n').TrimEnd();
        var begin = normalized.IndexOf(AgentsBeginMarker, StringComparison.Ordinal);
        var end = normalized.IndexOf(AgentsEndMarker, StringComparison.Ordinal);

        string updated;
        if (begin >= 0 && end > begin)
        {
            end += AgentsEndMarker.Length;
            updated = normalized[..begin].TrimEnd() + "\n\n" + normalizedBlock + "\n\n" + normalized[end..].TrimStart();
        }
        else
        {
            updated = normalized.TrimEnd();
            if (updated.Length > 0)
                updated += "\n\n";
            updated += normalizedBlock + "\n";
        }

        return updated.Replace("\n", newline);
    }

    private static string? ExtractForemanSection(string text)
    {
        var lines = NormalizeLines(text);
        var range = FindForemanSectionRange(lines);
        return range is null
            ? null
            : string.Join("\n", lines.Skip(range.Value.Start).Take(range.Value.EndExclusive - range.Value.Start));
    }

    private static (int Start, int EndExclusive)? FindForemanSectionRange(List<string> lines)
    {
        var start = -1;
        for (var i = 0; i < lines.Count; i++)
        {
            if (IsForemanHeader(lines[i]))
            {
                start = i;
                break;
            }
        }

        if (start < 0) return null;

        var end = lines.Count;
        for (var i = start + 1; i < lines.Count; i++)
        {
            if (!TryGetHeaderName(lines[i], out var header)) continue;
            if (!IsForemanHeaderName(header) && !IsForemanChildHeaderName(header))
            {
                end = i;
                break;
            }
        }

        return (start, end);
    }

    private static bool IsForemanHeader(string line) =>
        TryGetHeaderName(line, out var header) && IsForemanHeaderName(header);

    private static bool IsForemanHeaderName(string header) =>
        string.Equals(NormalizeHeader(header), SectionName, StringComparison.OrdinalIgnoreCase);

    private static bool IsForemanChildHeaderName(string header)
    {
        var normalized = NormalizeHeader(header);
        return normalized.StartsWith(SectionName + ".", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetHeaderName(string line, out string header)
    {
        header = "";
        var match = Regex.Match(line, @"^\s*\[([^\]]+)\]\s*(?:#.*)?$");
        if (!match.Success) return false;
        header = match.Groups[1].Value.Trim();
        return true;
    }

    private static string NormalizeHeader(string header)
    {
        var parts = header.Split('.');
        for (var i = 0; i < parts.Length; i++)
            parts[i] = parts[i].Trim().Trim('"', '\'');
        return string.Join(".", parts);
    }

    private static bool HasAssignment(string section, string key, string value)
    {
        var escaped = Regex.Escape(value);
        return Regex.IsMatch(
            section,
            $@"(?im)^\s*{Regex.Escape(key)}\s*=\s*""{escaped}""\s*(?:#.*)?$");
    }

    private static bool TryGetBearerTokenEnvVarName(string section, out string name)
    {
        var m = Regex.Match(section, @"(?im)^\s*bearer_token_env_var\s*=\s*""([^""]+)""\s*(?:#.*)?$");
        name = m.Success ? m.Groups[1].Value : "";
        return m.Success;
    }

    private static bool HasInlineAuthorizationHeader(string section) =>
        Regex.IsMatch(
            section,
            @"(?ims)^\s*http_headers\s*=\s*\{[^}]*Authorization\s*=\s*""Bearer\s+[^""]+""[^}]*\}\s*(?:#.*)?$");

    private static List<string> NormalizeLines(string text) =>
        text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n').ToList();

    private static string TomlEscape(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            sb.Append(c switch
            {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\b' => "\\b",
                '\t' => "\\t",
                '\n' => "\\n",
                '\f' => "\\f",
                '\r' => "\\r",
                _ => c,
            });
        }

        return sb.ToString();
    }
}
