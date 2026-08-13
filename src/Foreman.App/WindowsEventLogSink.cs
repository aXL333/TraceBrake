using System.Diagnostics;
using Foreman.Core.Models;
using Foreman.Core.Notifications;

namespace Foreman.App;

/// <summary>
/// Windows implementation of <see cref="IOsEventLogSink"/>: writes to the Application event log under the
/// legacy-compatible "Foreman Agent Safety" source so TraceBrake's lifecycle + significant events appear in Event Viewer
/// (Defender-style) and survive the app being killed. Registering the source needs admin ONCE — done by the
/// elevated sidecar (<c>Run Elevated</c>); until then this reports unavailable and TraceBrake keeps logging to disk.
/// Every write is best-effort and never throws — an OS-log problem must never disturb the watchdog.
/// </summary>
public sealed class WindowsEventLogSink : IOsEventLogSink
{
    private const string SourceName = OsEventLogNames.SourceName;
    private const string LogName = OsEventLogNames.LogName;

    private readonly bool _available;
    private readonly string? _reason;

    public WindowsEventLogSink()
    {
        try
        {
            if (EventLog.SourceExists(SourceName))
            {
                _available = true;
                return;
            }

            // Not registered yet. Creating a source needs admin; try anyway (succeeds if we happen to be elevated),
            // otherwise degrade gracefully — the elevated sidecar registers it on the next Run-Elevated launch.
            try
            {
                EventLog.CreateEventSource(new EventSourceCreationData(SourceName, LogName));
                _available = true;
            }
            catch
            {
                _available = false;
                _reason = "Windows Event Log source not registered — enable Run Elevated once (Settings) to register it. Logging to disk meanwhile.";
            }
        }
        catch (Exception ex)
        {
            _available = false;
            _reason = $"Windows Event Log unavailable: {ex.Message}";
        }
    }

    public bool IsAvailable => _available;
    public string? UnavailableReason => _reason;

    public void Write(int eventId, OsEventCategory category, ForemanSeverity severity, string message)
    {
        if (!_available) return;
        try
        {
            EventLog.WriteEntry(SourceName, Trim(message), MapType(severity), eventId, (short)category);
        }
        catch
        {
            // Transient Event Log failures (service churn, quota) must never propagate into the watchdog.
        }
    }

    /// <summary>
    /// Reads back this source's own recent entries, newest first — the durable external record TraceBrake uses on
    /// launch to detect an offline log rollback (the LogChainAnchor) and a prior hard-kill (the last lifecycle
    /// run-marker). The Application log is shared, so we filter to our source and bound the raw scan so a busy box
    /// can't make startup crawl. Best-effort: any failure yields an empty list (→ no false rollback/kill alarm).
    /// </summary>
    public IReadOnlyList<OsEventRecord> ReadOwnRecent(int maxEntries)
    {
        if (!_available || maxEntries <= 0) return [];
        var found = new List<OsEventRecord>(Math.Min(maxEntries, 64));
        try
        {
            using var log = new EventLog(LogName);
            var entries = log.Entries;
            var total = entries.Count;
            // Scan newest→oldest; stop once we have enough of OUR entries or we've examined a generous raw cap
            // (TraceBrake writes sparsely, so its recent entries can be spread across many other-source entries).
            const int rawScanCap = 20_000;
            var scanned = 0;
            for (var i = total - 1; i >= 0 && found.Count < maxEntries && scanned < rawScanCap; i--, scanned++)
            {
                EventLogEntry e;
                try { e = entries[i]; } catch { continue; }
                if (!string.Equals(e.Source, SourceName, StringComparison.Ordinal)) continue;
                var id = (int)(e.InstanceId & 0xFFFF);   // the event id as written via WriteEntry(..., eventId, ...)
                found.Add(new OsEventRecord(id, e.Message ?? string.Empty));
            }
        }
        catch
        {
            // Reading the event log can throw (access, service churn) — never let it disturb launch.
            return found;
        }
        return found;
    }

    private static EventLogEntryType MapType(ForemanSeverity s) => s switch
    {
        ForemanSeverity.Critical or ForemanSeverity.High => EventLogEntryType.Error,
        ForemanSeverity.Medium                           => EventLogEntryType.Warning,
        _                                                => EventLogEntryType.Information,
    };

    // A single Event Log entry is capped near 32 KB; keep entries compact and well under it.
    private static string Trim(string m) => m.Length <= 16_000 ? m : m[..16_000] + "…";
}
