using Foreman.Core.Models;

namespace Foreman.Monitor;

/// <summary>
/// Identifies whether a process is a known AI harness and which type.
/// Always sets HarnessType when a match is found.
/// Only sets IsHarness = true when that harness is not in the disabled set.
/// </summary>
public static class HarnessClassifier
{
    // ── per-harness exe names (lower-case) ────────────────────────────────
    private static readonly (string[] Exes, string[] NodeMarkers, string[] PyMarkers, string Id)[] _rules =
    [
        (
            ["claude-code.exe", "claude.exe"],
            ["@anthropic-ai/claude-code", "claude-code/dist", ".claude/", "claudecode"],
            [],
            "claude-code"
        ),
        (
            ["codex.exe"],
            ["@openai/codex", "codex/dist", "openai-codex"],
            [],
            "codex"
        ),
        (
            ["t3 code.exe", "t3code.exe", "t3-code.exe"],
            ["pingdotgg/t3code", "t3code/apps/desktop", @"t3code\apps\desktop",
             "t3 code/resources/app", @"t3 code\resources\app"],
            [],
            "t3-code"
        ),
        (
            ["opencode.exe", "opencode"],
            ["opencode-ai", "@opencode-ai", "opencode/bin", "opencode/dist", ".opencode/"],
            [],
            "opencode"
        ),
        (
            ["gemini.exe"],
            ["@google/gemini-cli", "@google-labs/gemini-cli", "gemini-cli/dist", "google-gemini-cli"],
            [],
            "gemini-cli"
        ),
        (
            ["q.exe", "amazon-q.exe", "cw.exe"],
            ["@aws/amazon-q-developer-cli", "amazon-q-developer-cli", "amazon-q/dist"],
            [],
            "amazon-q"
        ),
        (
            ["aider.exe", "aider"],
            [],                                          // aider doesn't run via node
            ["aider", "aider-chat", "-m aider", "__main__.py"],   // python markers
            "aider"
        ),
        (
            ["copilot.exe", "copilot", "gh.exe"],        // standalone GitHub Copilot CLI (@github/copilot) + legacy 'gh copilot' extension
            ["@github/copilot", "@github\\copilot", "@githubnext/github-copilot-cli", "github-copilot-cli", "gh-copilot", "copilot-cli"],
            [],
            "github-copilot"
        ),
        (
            ["cursor.exe", "cursor-tunnel.exe"],
            ["cursor/resources/app", "cursor-server", "cursor-rpc"],
            [],
            "cursor"
        ),
        (
            [],
            // Cline, Continue, Roo Code all run as VS Code extension host node processes
            ["cline", "saoudrizwan.claude-dev", "@continuedev/continue", "continue-server",
             "roo-cline", "roo-code", "roocline"],
            [],
            "cline"
        ),

        // ── Local-model hosts (HarnessCategory.LocalModelHost — exempt from hang/idle/orphan) ──────────────
        // Match only HIGH-CONFIDENCE, non-generic exe names: a false "local-model host" match would wrongly EXEMPT
        // an unrelated process from hang/orphan, so generic shared binaries (chat.exe/GPT4All, bare llama-server.exe,
        // bare python.exe) are deliberately NOT matched here — their inference children are covered via the harness
        // ancestor when parented by one of these hosts.
        (
            ["lm studio.exe", "lms.exe"],     // LM Studio GUI + its CLI (llama.cpp/MLX backend is a child)
            [], [],
            "lm-studio"
        ),
        (
            ["ollama.exe", "ollama app.exe"], // tray, `ollama serve`, AND the `ollama runner` inference child (same binary)
            [], [],
            "ollama"
        ),
        (
            ["jan.exe"],                      // Jan desktop (bundled llama-server child)
            [], [],
            "jan"
        ),
        (
            ["koboldcpp.exe", "koboldcpp_cu12.exe", "koboldcpp_nocuda.exe"],
            [], [],
            "koboldcpp"
        ),
        (
            ["local-ai.exe"],
            [], [],
            "localai"
        ),
        (
            [],                               // oobabooga runs as python.exe server.py — match a specific cmdline
            [],
            ["text-generation-webui", "oobabooga", "server.py --portable"],
            "text-generation-webui"
        ),
    ];

    public static void Classify(
        ProcessRecord record,
        IReadOnlySet<string>? disabledHarnesses = null,
        IEnumerable<string>? customHarnessExes  = null)
    {
        var nameLower = record.Name.ToLowerInvariant();
        var cmdLower  = record.CommandLine.ToLowerInvariant();
        var pathLower = record.ExecutablePath.Replace('/', '\\').ToLowerInvariant();

        // Desktop Claude's browser integration deliberately uses a generic executable name and can outlive the
        // visible app by days. Attribute only the high-confidence vendor-owned path/command combination; matching
        // every chrome-native-host.exe would fold unrelated extensions into Claude's tree.
        const string claudeNativeHost = @"\appdata\roaming\claude\chromenativehost\chrome-native-host.exe";
        if (nameLower == "chrome-native-host.exe"
            && (pathLower.EndsWith(claudeNativeHost, StringComparison.Ordinal)
                || cmdLower.Contains(claudeNativeHost, StringComparison.Ordinal)))
        {
            record.HarnessType = "claude-code";
            if (disabledHarnesses is null || !disabledHarnesses.Contains(record.HarnessType))
                record.IsHarness = true;
            return;
        }

        foreach (var (exes, nodeMarkers, pyMarkers, id) in _rules)
        {
            bool matched = false;

            // direct executable match
            foreach (var exe in exes)
                if (nameLower == exe) { matched = true; break; }

            // node.exe + command-line marker
            if (!matched && (nameLower is "node.exe" or "node") && nodeMarkers.Length > 0)
                foreach (var m in nodeMarkers)
                    if (cmdLower.Contains(m)) { matched = true; break; }

            // python.exe/python3.exe + command-line marker
            if (!matched && (nameLower is "python.exe" or "python3.exe" or "python" or "python3") && pyMarkers.Length > 0)
                foreach (var m in pyMarkers)
                    if (cmdLower.Contains(m)) { matched = true; break; }

            if (!matched) continue;

            // always write the type (so the Harnesses window can show running status)
            record.HarnessType = id;

            // only flag for active monitoring if not opted-out
            if (disabledHarnesses is null || !disabledHarnesses.Contains(id))
                record.IsHarness = true;

            return;
        }

        // ── custom exe names added by the user ────────────────────────────
        if (customHarnessExes is not null)
        {
            foreach (var exeName in customHarnessExes)
            {
                if (nameLower == exeName.ToLowerInvariant())
                {
                    var id = $"custom:{exeName.ToLowerInvariant()}";
                    record.HarnessType = id;
                    if (disabledHarnesses is null || !disabledHarnesses.Contains(id))
                        record.IsHarness = true;
                    return;
                }
            }
        }
    }
}
