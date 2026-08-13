namespace Foreman.Core.Security;

/// <summary>
/// Dead-man's switch (task #62): a periodic human tap-in. If the operator goes away for a long stretch WHILE
/// agents keep running, TraceBrake is effectively operating unattended — the window in which a rogue or
/// prompt-injected agent can do the most damage with nobody watching. Opt-in; raises one heads-up notice per
/// absence episode and re-arms when the operator returns.
/// </summary>
public sealed class DeadMansSwitchSettings
{
    /// <summary>Off by default — opt-in (some operators legitimately leave long agent runs unattended).</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>Operator-input absence (minutes) that, with agents still running, counts as "unattended". 4h default.</summary>
    public int AbsenceMinutes { get; set; } = 240;
}

/// <summary>Pure decision for the dead-man's switch — unit-tested; the timer/bus wiring is the Monitor part.</summary>
public static class DeadMansSwitchPolicy
{
    /// <summary>
    /// Fire once when the lock is on, the operator has been absent past the threshold, at least one harness is
    /// still running, and we haven't already fired for this episode.
    /// </summary>
    public static bool ShouldFire(int absenceMinutes, int activeHarnessCount, bool alreadyFired, DeadMansSwitchSettings s)
        => s.Enabled && !alreadyFired && activeHarnessCount > 0 && absenceMinutes >= s.AbsenceMinutes;

    /// <summary>Re-arm once the operator is back (recent input below the threshold), so the next absence can fire.</summary>
    public static bool ShouldRearm(int absenceMinutes, DeadMansSwitchSettings s)
        => absenceMinutes < s.AbsenceMinutes;
}
