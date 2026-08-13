using System.Threading;

namespace Foreman.Core.Settings;

/// <summary>Declared route by which a settings write reached <see cref="SettingsStore"/>.</summary>
public enum SettingsChangeOrigin
{
    Unattributed,
    HumanUi,
    AuthenticatedMcp,
    InternalRuntime,
    StartupMigration,
}

/// <summary>Input evidence captured when a TraceBrake UI action began.</summary>
public enum SettingsInputProvenance
{
    NotApplicable,
    Physical,
    Injected,
    ForemanComputerUse,
    Unattributed,
}

public sealed record SettingsChangeAttribution(
    SettingsChangeOrigin Origin,
    string Actor,
    string Operation,
    SettingsInputProvenance InputProvenance,
    bool Suspicious,
    string Reason,
    DateTimeOffset CapturedAt)
{
    public static SettingsChangeAttribution Unattributed(string operation = "settings-save") => new(
        SettingsChangeOrigin.Unattributed,
        "unknown",
        Bound(operation),
        SettingsInputProvenance.Unattributed,
        true,
        "No trusted settings-change route was declared.",
        DateTimeOffset.UtcNow);

    public static SettingsChangeAttribution Declared(
        SettingsChangeOrigin origin,
        string actor,
        string operation,
        SettingsInputProvenance input = SettingsInputProvenance.NotApplicable,
        bool suspicious = false,
        string reason = "Declared trusted route.") => new(
            origin, Bound(actor), Bound(operation), input, suspicious, Bound(reason), DateTimeOffset.UtcNow);

    private static string Bound(string? value)
    {
        var clean = string.IsNullOrWhiteSpace(value) ? "unknown" : value.Trim();
        return clean.Length <= 160 ? clean : clean[..160];
    }
}

/// <summary>
/// Async-flow provenance for a settings mutation. UI and authenticated protocol entry points establish a scope;
/// any nested save (including one after an await) inherits it. Unscoped saves remain explicitly suspicious.
/// </summary>
public static class SettingsChangeContext
{
    private static readonly AsyncLocal<SettingsChangeAttribution?> CurrentValue = new();

    public static SettingsChangeAttribution? Current => CurrentValue.Value;

    public static IDisposable Begin(SettingsChangeAttribution attribution)
    {
        ArgumentNullException.ThrowIfNull(attribution);
        var prior = CurrentValue.Value;
        CurrentValue.Value = attribution;
        return new Scope(prior);
    }

    private sealed class Scope(SettingsChangeAttribution? prior) : IDisposable
    {
        private SettingsChangeAttribution? _prior = prior;
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed) return;
            CurrentValue.Value = _prior;
            _prior = null;
            _disposed = true;
        }
    }
}

/// <summary>Pure policy used by the Win32 input monitor and unit tests.</summary>
public static class SettingsInputProvenancePolicy
{
    public static SettingsInputProvenance Assess(
        long now,
        long lastPhysical,
        long lastInjected,
        bool lastInjectedWasForeman,
        long freshness)
    {
        static bool Fresh(long nowValue, long seen, long window) =>
            seen > 0 && nowValue >= seen && nowValue - seen <= window;

        var physicalFresh = Fresh(now, lastPhysical, freshness);
        var injectedFresh = Fresh(now, lastInjected, freshness);

        // When both are recent, the last event that could have initiated the action wins. Prefer injected on a tie:
        // ambiguity must not be laundered into a claim of physical presence.
        if (injectedFresh && (!physicalFresh || lastInjected >= lastPhysical))
            return lastInjectedWasForeman
                ? SettingsInputProvenance.ForemanComputerUse
                : SettingsInputProvenance.Injected;
        if (physicalFresh)
            return SettingsInputProvenance.Physical;
        return SettingsInputProvenance.Unattributed;
    }
}

/// <summary>Secret-free evidence emitted only after a settings save completed.</summary>
public sealed record SettingsSaveAudit(
    DateTimeOffset Timestamp,
    SettingsChangeAttribution Attribution,
    bool SettingsChanged,
    bool SecurityProjectionChanged,
    string PriorSecurityProjectionHash,
    string CurrentSecurityProjectionHash);
