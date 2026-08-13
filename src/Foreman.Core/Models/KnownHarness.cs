namespace Foreman.Core.Models;

/// <summary>What kind of harness this is — drives idle/hang/orphan expectations.</summary>
public enum HarnessCategory
{
    /// <summary>An AI coding agent (Claude Code, Codex, …): bursty I/O, idle = possibly stalled.</summary>
    CodingAgent,
    /// <summary>
    /// A local-model chat/inference host (LM Studio, Ollama, Jan, …). Its backend inference server is
    /// LONG-LIVED and sits I/O-silent between prompts BY DESIGN, so hang / idle-cleanup / orphan rules tuned for
    /// coding agents would false-positive on it. TraceBrake still tracks it and applies a profile, but exempts it
    /// from those idle-driven signals.
    /// </summary>
    LocalModelHost,
}

/// <summary>Static metadata about a supported harness.</summary>
public sealed record KnownHarness(
    string Id,
    string DisplayName,
    string Developer,
    string Description,
    HarnessCategory Category = HarnessCategory.CodingAgent
);

/// <summary>
/// Registry of all harnesses TraceBrake knows how to detect.
/// IDs must match what HarnessClassifier.Classify() writes into ProcessRecord.HarnessType.
/// </summary>
public static class KnownHarnesses
{
    public static readonly IReadOnlyList<KnownHarness> All =
    [
        new("claude-code",    "Claude Code",            "Anthropic",         "AI coding agent with file editing and bash execution"),
        new("codex",          "Codex",                  "OpenAI",            "OpenAI's AI coding agent — CLI and Desktop app (same engine, shared ~/.codex config)"),
        new("t3-code",        "T3 Code",                "T3 Tools",          "Open-source control plane for coding agents"),
        new("opencode",       "OpenCode",               "Anomaly",           "Open-source terminal and desktop AI coding agent"),
        new("gemini-cli",     "Gemini CLI",             "Google",            "Google's terminal-based AI coding agent"),
        new("amazon-q",       "Amazon Q Developer",     "Amazon / AWS",      "AWS AI development assistant CLI"),
        new("aider",          "Aider",                  "Paul Gauthier",     "AI pair programming in your terminal"),
        new("github-copilot", "GitHub Copilot CLI",     "GitHub / Microsoft","GitHub's terminal 'copilot' CLI (@github/copilot); also the legacy 'gh copilot' extension"),
        new("cursor",         "Cursor",                 "Anysphere",         "AI-first code editor (VS Code fork)"),
        new("cline",          "Cline / Continue / Roo", "Community",         "VS Code AI coding extensions (Cline, Continue, Roo Code)"),

        // ── Local-model chat / inference hosts ────────────────────────────────────────────────────────────
        // TraceBrake tracks these like any harness, but their inference servers idle between prompts BY DESIGN, so
        // HarnessCategory.LocalModelHost exempts them from the hang / idle-cleanup / orphan signals (see KnownHarnesses.IsLocalModelHost).
        new("lm-studio",             "LM Studio",             "LM Studio",       "Local LLM desktop host (llama.cpp/MLX), OpenAI-compatible API on :1234", HarnessCategory.LocalModelHost),
        new("ollama",                "Ollama",                "Ollama",          "Local LLM server + model runner, API on :11434",                        HarnessCategory.LocalModelHost),
        new("jan",                   "Jan",                   "Menlo Research",  "Local LLM desktop host (llama.cpp), API on :1337",                      HarnessCategory.LocalModelHost),
        new("koboldcpp",             "KoboldCpp",             "Community",       "Single-binary local LLM server (llama.cpp), API on :5001",              HarnessCategory.LocalModelHost),
        new("localai",               "LocalAI",               "Ettore Di Giacinto", "Self-hosted OpenAI-compatible local inference server on :8080",      HarnessCategory.LocalModelHost),
        new("text-generation-webui", "Text Generation WebUI", "oobabooga",       "Gradio local-LLM web UI + API (Transformers/ExLlama/llama.cpp)",         HarnessCategory.LocalModelHost),
    ];

    public static KnownHarness? GetById(string id) =>
        All.FirstOrDefault(h => h.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True if <paramref name="harnessType"/> is a local-model host (LM Studio, Ollama, …) whose inference server
    /// idles by design — so the hang / idle-cleanup / orphan detectors should not treat its quiet as a problem.
    /// Tolerates null and custom ids (custom harnesses are coding-agent by default).
    /// </summary>
    public static bool IsLocalModelHost(string? harnessType) =>
        harnessType is not null && GetById(harnessType)?.Category == HarnessCategory.LocalModelHost;
}
