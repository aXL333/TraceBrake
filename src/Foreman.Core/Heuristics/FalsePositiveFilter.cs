using Foreman.Core.Models;
using Foreman.Core.Profiles;
using System.Text.RegularExpressions;

namespace Foreman.Core.Heuristics;

/// <summary>
/// Suppresses known-safe matches to reduce noise.
/// </summary>
public static class FalsePositiveFilter
{
    // Launcher hygiene exemptions are code-reviewed, rule-specific exceptions — never a general severity bypass.
    // Keeping this allowlist in code means a disk profile cannot nominate a new High/Critical rule for suppression.
    private static readonly HashSet<string> _launcherHygieneRuleAllowlist = new(StringComparer.OrdinalIgnoreCase)
    {
        "win-002", // PowerShell ExecutionPolicy Bypass used by a verified harness hook script path.
    };

    // Process names whose OWN command lines are low-signal noise: TraceBrake itself and dev test runners.
    // NOTE: a basename is NOT an identity — a monitored agent runs as the same user and can name its dropper
    // anything. So this set is only ever consulted to drop sub-Medium NOISE (see IsSuppressed); it can never
    // silence a security-significant rule, which is what made name-spoofing a total-bypass before.
    private static readonly HashSet<string> _suppressedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Foreman.App",
        "Foreman.App.exe",
        "Foreman",
        "Foreman.exe",
        "TraceBrake.exe",
        "dotnet",         // test runners
        "xunit.console",
        "pytest",
        "vstest.console",
    };

    public static bool IsSuppressed(
        PatternRule rule,
        string commandLine,
        string? processName,
        HarnessProfile? profile = null)
    {
        // CRITICAL: process-name suppression must NEVER silence a security-significant rule. The adversary is a
        // same-user agent that can name its process "Foreman.exe"/"dotnet"/"pytest"; if name-suppression covered
        // all rules, copying a dropper to such a name would disable the entire command heuristic engine (rm -rf,
        // mimikatz, curl|bash, the decoy sentinel). Credential/exec/destruction/decoy rules are all Medium+, so
        // gating name-suppression to sub-Medium rules makes them fire regardless of what the agent calls itself,
        // while still dropping genuine low-signal noise from TraceBrake's own process / test runners.
        if (processName is not null
            && rule.ParsedSeverity < ForemanSeverity.Medium
            && _suppressedProcesses.Contains(processName))
            return true;

        if (IsLauncherHygieneSuppressed(rule, commandLine, profile))
            return true;

        return false;
    }

    private static bool IsLauncherHygieneSuppressed(
        PatternRule rule,
        string commandLine,
        HarnessProfile? profile)
    {
        if (rule.ParsedSeverity > ForemanSeverity.Medium ||
            !_launcherHygieneRuleAllowlist.Contains(rule.Id))
            return false;

        var profileRules = profile?.Alerts.LauncherSuppressedRuleIds ?? [];
        var profileMarkers = profile?.Alerts.TrustedHookPathMarkers ?? [];
        if (profileRules.Contains(rule.Id, StringComparer.OrdinalIgnoreCase) &&
            ContainsAnyMarker(commandLine, profileMarkers))
        {
            return true;
        }

        foreach (var integration in HarnessIntegrationRegistry.All)
        {
            if (!integration.LauncherSuppressedRuleIds.Contains(rule.Id, StringComparer.OrdinalIgnoreCase))
                continue;
            if (ContainsAnyMarker(commandLine, integration.TrustedHookPathMarkers))
                return true;
        }

        return false;
    }

    // Script extensions a launcher-hygiene exemption may legitimately apply to.
    private const string _hookScriptTail = @"[^\s""'|;&]*\.(?:ps1|psm1|cmd|bat|sh|py)\b";

    private static bool ContainsAnyMarker(string commandLine, IEnumerable<string> markers)
    {
        // A trusted-hook marker must PREFIX the actually-launched script path (…/.claude/hooks/foo.ps1), not just
        // appear somewhere on the line. Otherwise a same-user agent forges the exemption with a harmless token
        // like `echo .claude/hooks/ ; <malicious>` and silences the execution-policy-bypass rule for free.
        foreach (var marker in markers)
        {
            if (string.IsNullOrEmpty(marker)) continue;
            try
            {
                if (Regex.IsMatch(commandLine, Regex.Escape(marker) + _hookScriptTail,
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)))
                    return true;
            }
            catch (RegexMatchTimeoutException) { /* pathological input — treat as no match */ }
        }
        return false;
    }
}
