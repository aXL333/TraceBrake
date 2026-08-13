using Foreman.Core.Events;
using Foreman.Core.Models;
using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;

namespace Foreman.Monitor;

public sealed record HarnessAppModelFailure(
    DateTimeOffset Timestamp,
    int EventId,
    string HarnessId,
    string HarnessName,
    string PackageFullName,
    string ErrorCode,
    string FailureKind);

/// <summary>Pure parser for Windows packaged-app launch failures that happen before a harness process exists.</summary>
public static partial class HarnessAppModelFailurePolicy
{
    public static HarnessAppModelFailure? Parse(int eventId, DateTimeOffset timestamp, string? message)
    {
        if (eventId is not (208 or 215) || string.IsNullOrWhiteSpace(message)) return null;
        var package = PackageRegex().Match(message).Groups["package"].Value.TrimEnd('.', ',', ';');
        if (package.Length == 0) return null;

        var harness = ResolveHarness(package);
        if (harness is null) return null;

        var error = ErrorRegex().Match(message).Value.ToUpperInvariant();
        if (error.Length == 0) error = "unknown";
        var kind = message.Contains("converting the job", StringComparison.OrdinalIgnoreCase)
            ? "Desktop AppX job conversion failed"
            : message.Contains("configuring runtime", StringComparison.OrdinalIgnoreCase)
                ? "packaged runtime configuration failed"
                : "packaged application launch failed";
        return new HarnessAppModelFailure(
            timestamp, eventId, harness.Value.Id, harness.Value.Name, package, error, kind);
    }

    private static (string Id, string Name)? ResolveHarness(string package) => package switch
    {
        var value when value.StartsWith("Claude_", StringComparison.OrdinalIgnoreCase)
            => ("claude-code", "Claude"),
        var value when value.Contains("Codex", StringComparison.OrdinalIgnoreCase)
            => ("codex", "Codex"),
        var value when value.StartsWith("Cursor", StringComparison.OrdinalIgnoreCase)
            => ("cursor", "Cursor"),
        _ => null,
    };

    [GeneratedRegex(@"\bpackage\s+(?<package>[A-Za-z0-9._-]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PackageRegex();

    [GeneratedRegex(@"0x[0-9a-fA-F]{8}", RegexOptions.CultureInvariant)]
    private static partial Regex ErrorRegex();
}

/// <summary>
/// Watches AppModel-Runtime failures for known packaged harnesses. These failures precede process creation, so WMI
/// process monitoring alone can never see them. Duplicate 208/215 events from one activation are coalesced.
/// </summary>
internal sealed class HarnessAppModelFailureMonitor : IDisposable
{
    private static readonly TimeSpan RepeatCooldown = TimeSpan.FromMinutes(2);
    private readonly EventBus _bus;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastPublished =
        new(StringComparer.OrdinalIgnoreCase);
    private EventLogWatcher? _watcher;

    public HarnessAppModelFailureMonitor(EventBus bus) => _bus = bus;

    public void Start()
    {
        if (_watcher is not null) return;
        try
        {
            var query = new EventLogQuery(
                "Microsoft-Windows-AppModel-Runtime/Admin",
                PathType.LogName,
                "*[System[(EventID=208 or EventID=215) and Level=2]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;
        }
        catch (Exception ex)
        {
            _watcher?.Dispose();
            _watcher = null;
            _bus.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow,
                ForemanSeverity.Medium,
                "Foreman.AppModel",
                $"Packaged-harness launch monitoring could not start ({ex.GetType().Name}). Process monitoring continues, " +
                "but failures that occur before a harness process is created may be missed."));
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null || args.EventRecord is not { } record) return;
        using (record)
        {
            HarnessAppModelFailure? failure;
            try
            {
                failure = HarnessAppModelFailurePolicy.Parse(
                    record.Id,
                    record.TimeCreated is { } time ? new DateTimeOffset(time) : DateTimeOffset.UtcNow,
                    record.FormatDescription());
            }
            catch { return; }
            if (failure is null || !ShouldPublish(failure)) return;

            var sharingHint = string.Equals(failure.ErrorCode, "0X80070020", StringComparison.OrdinalIgnoreCase)
                ? " Windows reported a sharing violation; a stale helper, packaged service, or interrupted update may still own the app job."
                : string.Empty;
            _bus.Publish(new MonitoringNoticeEvent(
                failure.Timestamp,
                ForemanSeverity.High,
                "Foreman.AppModel",
                $"Windows blocked {failure.HarnessName} before its main process started: {failure.FailureKind} " +
                $"({failure.ErrorCode}, AppModel event {failure.EventId}, package {failure.PackageFullName})." +
                sharingHint));
        }
    }

    private bool ShouldPublish(HarnessAppModelFailure failure)
    {
        var key = $"{failure.HarnessId}|{failure.ErrorCode}";
        while (true)
        {
            if (!_lastPublished.TryGetValue(key, out var prior))
                return _lastPublished.TryAdd(key, failure.Timestamp);
            if (failure.Timestamp - prior < RepeatCooldown) return false;
            if (_lastPublished.TryUpdate(key, failure.Timestamp, prior)) return true;
        }
    }

    public void Dispose()
    {
        if (_watcher is null) return;
        try { _watcher.Enabled = false; } catch { }
        _watcher.EventRecordWritten -= OnEventRecordWritten;
        _watcher.Dispose();
        _watcher = null;
    }
}
