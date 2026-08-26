namespace Foreman.Core.Mcp;

public enum HarnessCapabilityAccess
{
    Allow,
    AskFirst,
    Block,
}

public sealed class HarnessCapabilityRestrictions
{
    public HarnessCapabilityAccess ComputerUse { get; set; } = HarnessCapabilityAccess.AskFirst;
    public HarnessCapabilityAccess BrowserUse { get; set; } = HarnessCapabilityAccess.AskFirst;
}

public sealed record HarnessCapabilityDecision(
    HarnessCapabilityAccess Access,
    bool Allowed,
    string Reason);

public static class HarnessCapabilityPolicy
{
    // Return a fresh value so one caller cannot mutate the process-wide fallback authority for every harness.
    public static HarnessCapabilityRestrictions Defaults => new();

    public static HarnessCapabilityRestrictions Effective(
        IReadOnlyDictionary<string, HarnessCapabilityRestrictions> configured,
        string? harnessId)
    {
        if (!string.IsNullOrWhiteSpace(harnessId)
            && configured.TryGetValue(harnessId, out var restrictions)
            && restrictions is not null)
        {
            return restrictions;
        }

        return Defaults;
    }

    public static HarnessCapabilityDecision EvaluateBrowserUse(HarnessCapabilityRestrictions restrictions)
        => Evaluate(restrictions.BrowserUse, "Browser use is restricted for this harness.");

    public static HarnessCapabilityDecision EvaluateComputerUse(HarnessCapabilityRestrictions restrictions)
        => Evaluate(restrictions.ComputerUse, "Computer use is restricted for this harness.");

    private static HarnessCapabilityDecision Evaluate(HarnessCapabilityAccess access, string restrictedReason)
        => access switch
        {
            HarnessCapabilityAccess.Allow => new(access, true, "Allowed by harness policy."),
            HarnessCapabilityAccess.AskFirst => new(access, false, restrictedReason + " Ask the operator first."),
            HarnessCapabilityAccess.Block => new(access, false, restrictedReason + " Blocked by operator policy."),
            _ => new(HarnessCapabilityAccess.Block, false, restrictedReason + " Unknown policy value."),
        };
}
