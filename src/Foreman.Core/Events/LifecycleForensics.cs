using Foreman.Core.Notifications;

namespace Foreman.Core.Events;

/// <summary>How the PRIOR TraceBrake instance ended, reconstructed from the OS event log on the next launch.</summary>
public enum PriorShutdown
{
    /// <summary>No prior run-marker found (first run, or the OS event log is unavailable).</summary>
    Unknown,
    /// <summary>The prior instance recorded a clean <see cref="OsEventIds.StoppedClean"/>.</summary>
    Clean,
    /// <summary>The prior instance recorded a fatal crash — already alerted at the time.</summary>
    Crashed,
    /// <summary>
    /// The prior instance left a DANGLING run (a <c>Started</c>, or a handled crash it survived, with no terminal
    /// marker after it). A clean stop and a crash both get a chance to write a terminal event; a hard
    /// <c>TerminateProcess</c> does not. So a dangling run is the signature of the watchdog being KILLED — the
    /// "watchdog-of-the-watchdog" signal, which (being reconstructed on the next life and re-logged) survives the kill.
    /// </summary>
    Killed,
}

/// <summary>
/// Reconstructs how the previous TraceBrake instance terminated by reading the lifecycle run-markers it left in the
/// OS event log. Pure over the records the platform sink hands back, so it's fully testable without an OS log.
/// </summary>
public static class LifecycleForensics
{
    // The events that bound a run. NOT the per-record LogChainAnchor (also in the lifecycle id range) — that's a
    // rollback witness, not a start/stop/crash marker, so it must not be read as one.
    private static readonly HashSet<int> _runMarkers = new()
    {
        OsEventIds.Started,
        OsEventIds.StoppedClean,
        OsEventIds.CrashHandled,
        OsEventIds.CrashFatal,
        OsEventIds.CrashUnobservedTask,
    };

    /// <summary>The most recent run-marker event id from records ordered NEWEST-FIRST, or null if none present.</summary>
    public static int? LastRunMarker(IReadOnlyList<OsEventRecord> recentNewestFirst)
    {
        foreach (var r in recentNewestFirst)
            if (_runMarkers.Contains(r.EventId)) return r.EventId;
        return null;
    }

    /// <summary>Classifies the prior shutdown from its last run-marker.</summary>
    public static PriorShutdown Classify(int? lastRunMarker) => lastRunMarker switch
    {
        null                              => PriorShutdown.Unknown,
        OsEventIds.StoppedClean           => PriorShutdown.Clean,
        OsEventIds.CrashFatal             => PriorShutdown.Crashed,
        OsEventIds.CrashUnobservedTask    => PriorShutdown.Crashed,
        // Started (ran but never recorded a terminal event) or CrashHandled (survived, then vanished) = a hard kill.
        _                                 => PriorShutdown.Killed,
    };

    /// <summary>Convenience: read the recent OS-log records and classify the prior shutdown in one call.</summary>
    public static PriorShutdown ClassifyFrom(IReadOnlyList<OsEventRecord> recentNewestFirst) =>
        Classify(LastRunMarker(recentNewestFirst));
}
