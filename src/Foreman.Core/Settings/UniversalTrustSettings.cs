using Foreman.Core.ComputerUse;
using Foreman.Core.Mcp;

namespace Foreman.Core.Settings;

/// <summary>
/// How much standing authority a harness receives for one capability. Values are ordered from least to most
/// permissive so policy relaxations can be detected consistently by the presence-lock UI.
/// </summary>
public enum TrustPrivilegeMode
{
    Never = 0,
    AskEveryTime = 1,
    UnattendedWhileUnlocked = 2,
    UnattendedIncludingLocked = 3,
}

/// <summary>The browser/desktop/Android capability policy attached to one universal Trust level.</summary>
public sealed class TrustCapabilityProfile
{
    public TrustPrivilegeMode BrowserObservation { get; set; } = TrustPrivilegeMode.UnattendedWhileUnlocked;
    public TrustPrivilegeMode BrowserControl { get; set; } = TrustPrivilegeMode.AskEveryTime;
    public TrustPrivilegeMode DesktopObservation { get; set; } = TrustPrivilegeMode.AskEveryTime;
    public TrustPrivilegeMode DesktopControl { get; set; } = TrustPrivilegeMode.AskEveryTime;
    public TrustPrivilegeMode AdbObservation { get; set; } = TrustPrivilegeMode.UnattendedWhileUnlocked;
    public TrustPrivilegeMode AdbControl { get; set; } = TrustPrivilegeMode.AskEveryTime;

    public TrustCapabilityProfile Clone() => new()
    {
        BrowserObservation = BrowserObservation,
        BrowserControl = BrowserControl,
        DesktopObservation = DesktopObservation,
        DesktopControl = DesktopControl,
        AdbObservation = AdbObservation,
        AdbControl = AdbControl,
    };

    public TrustPrivilegeMode ModeFor(CuAction action)
    {
        var control = CuVerbs.IsStateChanging(action.Verb);
        return action.Modality switch
        {
            CuModality.Browser => control ? BrowserControl : BrowserObservation,
            CuModality.Desktop => control ? DesktopControl : DesktopObservation,
            CuModality.Android => control ? AdbControl : AdbObservation,
            _ => TrustPrivilegeMode.Never,
        };
    }

    /// <summary>Old per-harness Allow/AskFirst/Block settings remain a restrictive overlay during migration.</summary>
    public TrustCapabilityProfile ApplyLegacyRestrictions(HarnessCapabilityRestrictions? restrictions)
    {
        var effective = Clone();
        if (restrictions is null) return effective;

        effective.BrowserObservation = Overlay(restrictions.BrowserUse, effective.BrowserObservation);
        effective.BrowserControl = Overlay(restrictions.BrowserUse, effective.BrowserControl);
        effective.DesktopObservation = Overlay(restrictions.ComputerUse, effective.DesktopObservation);
        effective.DesktopControl = Overlay(restrictions.ComputerUse, effective.DesktopControl);
        effective.AdbObservation = Overlay(restrictions.ComputerUse, effective.AdbObservation);
        effective.AdbControl = Overlay(restrictions.ComputerUse, effective.AdbControl);
        return effective;

        static TrustPrivilegeMode Overlay(HarnessCapabilityAccess access, TrustPrivilegeMode current) => access switch
        {
            HarnessCapabilityAccess.Block => TrustPrivilegeMode.Never,
            HarnessCapabilityAccess.AskFirst => TrustPrivilegeMode.AskEveryTime,
            _ => current,
        };
    }

    public IEnumerable<TrustPrivilegeMode> Modes()
    {
        yield return BrowserObservation;
        yield return BrowserControl;
        yield return DesktopObservation;
        yield return DesktopControl;
        yield return AdbObservation;
        yield return AdbControl;
    }
}

/// <summary>
/// Editable, universal capability profiles for Trust 1–5. The default level (3) can observe browser/Android state
/// unattended only while the workstation is unlocked, and all state-changing work asks. Locked-down levels tighten
/// from there; unattended locked-session browser control exists only at an explicit Trust 5.
/// </summary>
public sealed class UniversalTrustSettings
{
    public Dictionary<int, TrustCapabilityProfile> Profiles { get; set; } = CreateDefaults();

    public TrustCapabilityProfile ForLevel(int level)
    {
        var key = Math.Clamp(level, 1, 5);
        if (Profiles is not null && Profiles.TryGetValue(key, out var profile) && profile is not null)
            return profile;
        return CreateDefaultProfile(key);
    }

    public static Dictionary<int, TrustCapabilityProfile> CreateDefaults() =>
        Enumerable.Range(1, 5).ToDictionary(level => level, CreateDefaultProfile);

    public static TrustCapabilityProfile CreateDefaultProfile(int level = 3) => Math.Clamp(level, 1, 5) switch
    {
        1 => new TrustCapabilityProfile
        {
            BrowserObservation = TrustPrivilegeMode.AskEveryTime,
            BrowserControl = TrustPrivilegeMode.Never,
            DesktopObservation = TrustPrivilegeMode.Never,
            DesktopControl = TrustPrivilegeMode.Never,
            AdbObservation = TrustPrivilegeMode.AskEveryTime,
            AdbControl = TrustPrivilegeMode.Never,
        },
        2 => new TrustCapabilityProfile
        {
            BrowserObservation = TrustPrivilegeMode.UnattendedWhileUnlocked,
            BrowserControl = TrustPrivilegeMode.AskEveryTime,
            DesktopObservation = TrustPrivilegeMode.AskEveryTime,
            DesktopControl = TrustPrivilegeMode.AskEveryTime,
            AdbObservation = TrustPrivilegeMode.UnattendedWhileUnlocked,
            AdbControl = TrustPrivilegeMode.AskEveryTime,
        },
        3 => new TrustCapabilityProfile(),
        4 => new TrustCapabilityProfile
        {
            BrowserObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            BrowserControl = TrustPrivilegeMode.UnattendedWhileUnlocked,
            DesktopObservation = TrustPrivilegeMode.AskEveryTime,
            DesktopControl = TrustPrivilegeMode.AskEveryTime,
            AdbObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            AdbControl = TrustPrivilegeMode.AskEveryTime,
        },
        _ => new TrustCapabilityProfile
        {
            BrowserObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            BrowserControl = TrustPrivilegeMode.UnattendedIncludingLocked,
            DesktopObservation = TrustPrivilegeMode.AskEveryTime,
            DesktopControl = TrustPrivilegeMode.AskEveryTime,
            AdbObservation = TrustPrivilegeMode.UnattendedIncludingLocked,
            AdbControl = TrustPrivilegeMode.AskEveryTime,
        },
    };

    public UniversalTrustSettings Clone() => new()
    {
        Profiles = Enumerable.Range(1, 5).ToDictionary(level => level, level => ForLevel(level).Clone()),
    };

    public string[] SecurityProjection() => Enumerable.Range(1, 5)
        .Select(level =>
        {
            var p = ForLevel(level);
            return $"{level}={(int)p.BrowserObservation}:{(int)p.BrowserControl}:" +
                   $"{(int)p.DesktopObservation}:{(int)p.DesktopControl}:" +
                   $"{(int)p.AdbObservation}:{(int)p.AdbControl}";
        })
        .ToArray();
}

public sealed record TrustCapabilityDecision(bool Blocked, bool RequiresApproval, string Reason)
{
    public static TrustCapabilityDecision Allow(string reason = "Allowed by universal Trust policy.") =>
        new(false, false, reason);
}

public static class TrustCapabilityPolicy
{
    public static TrustCapabilityDecision Evaluate(TrustPrivilegeMode mode, bool sessionLocked) => mode switch
    {
        TrustPrivilegeMode.Never => new(true, false, "Blocked by universal Trust policy (Never)."),
        TrustPrivilegeMode.AskEveryTime => new(false, true, "Universal Trust policy requires operator approval."),
        TrustPrivilegeMode.UnattendedWhileUnlocked when sessionLocked =>
            new(false, true, "Windows is locked; this Trust policy permits unattended use only while unlocked."),
        TrustPrivilegeMode.UnattendedWhileUnlocked => TrustCapabilityDecision.Allow("Allowed unattended while Windows is unlocked."),
        TrustPrivilegeMode.UnattendedIncludingLocked => TrustCapabilityDecision.Allow("Allowed unattended, including while Windows is locked."),
        _ => new(true, false, "Blocked because the universal Trust policy value is unknown."),
    };

    public static bool IsRelaxation(TrustCapabilityProfile before, TrustCapabilityProfile after) =>
        before.Modes().Zip(after.Modes(), (oldMode, newMode) => newMode > oldMode).Any(relaxed => relaxed);
}
