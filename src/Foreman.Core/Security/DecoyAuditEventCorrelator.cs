using Foreman.Core.Ipc;

namespace Foreman.Core.Security;

public sealed record DecoyAuditAccessEvent(
    int EventId,
    string? ObjectName,
    int ProcessId,
    string? ProcessImage,
    string? HandleId,
    uint AccessMask);

/// <summary>Correlates Security 4663 object names with the later 4660 deletion event.</summary>
public sealed class DecoyAuditEventCorrelator
{
    public const uint ReadData = 0x1;
    public const uint WriteData = 0x2;
    public const uint Delete = 0x10000;

    private readonly string[] _paths;
    private readonly int[] _excluded;
    private readonly Dictionary<string, (string Path, string Image)> _pendingDeletes = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public DecoyAuditEventCorrelator(IEnumerable<string> paths, IEnumerable<int> excluded)
    {
        _paths = paths.ToArray();
        _excluded = excluded.ToArray();
    }

    public IReadOnlyList<DecoyReadMessage> Process(DecoyAuditAccessEvent evt)
    {
        if (evt.ProcessId == 0) return [];
        var key = $"{evt.ProcessId}:{evt.HandleId}";
        if (evt.EventId == 4660)
        {
            (string Path, string Image) prior;
            lock (_gate)
            {
                if (string.IsNullOrWhiteSpace(evt.HandleId) || !_pendingDeletes.Remove(key, out prior)) return [];
            }
            return [Message(prior.Path, evt.ProcessId, evt.ProcessImage ?? prior.Image, "deleted")];
        }

        if (evt.EventId != 4663 ||
            !DecoyAuditPolicy.IsDecoyRead(evt.ObjectName, evt.ProcessId, evt.ProcessImage, _paths, _excluded))
            return [];

        var results = new List<DecoyReadMessage>();
        if ((evt.AccessMask & ReadData) != 0)
            results.Add(Message(evt.ObjectName!, evt.ProcessId, evt.ProcessImage, "read"));
        if ((evt.AccessMask & WriteData) != 0)
            results.Add(Message(evt.ObjectName!, evt.ProcessId, evt.ProcessImage, "modified"));
        if ((evt.AccessMask & Delete) != 0 && !string.IsNullOrWhiteSpace(evt.HandleId))
        {
            lock (_gate)
            {
                if (_pendingDeletes.Count >= 1024) _pendingDeletes.Clear();
                _pendingDeletes[key] = (evt.ObjectName!, evt.ProcessImage ?? string.Empty);
            }
        }
        return results;
    }

    private static DecoyReadMessage Message(string path, int pid, string? image, string operation) => new()
    {
        TimestampUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        Path = path,
        Pid = pid,
        Image = image ?? string.Empty,
        Operation = operation,
    };
}
