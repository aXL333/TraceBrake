namespace Foreman.Core.Ipc;

/// <summary>Frame kinds the elevated sidecar can stream over the shared one-way pipe.</summary>
public static class SidecarFrame
{
    public const string Net = "net";
    public const string DecoyRead = "decoyRead";
    public const string DecoyAuditStatus = "decoyAuditStatus";
    public const string WakeRequests = "wakeRequests";
}

/// <summary>
/// One frame streamed from the elevated ETW sidecar to the app: per-process network throughput.
/// Serialized as a single line of JSON over the local pipe. Kept in Foreman.Core so both the
/// sidecar and the app share one contract.
/// </summary>
public sealed class NetworkRatesMessage
{
    /// <summary>Frame discriminator on the shared pipe; the app routes by it. Missing = treated as "net".</summary>
    public string Kind { get; set; } = SidecarFrame.Net;

    public long TimestampUnixMs { get; set; }

    /// <summary>PID → bytes/sec (send + receive) measured over the sidecar's sampling interval.</summary>
    public Dictionary<int, double> Rates { get; set; } = new();
}

/// <summary>
/// One frame from the elevated sidecar: a READ of a decoy credential file was observed via Windows
/// SACL auditing (Security Event 4663). The sidecar has already confirmed the path is a tracked decoy
/// and the reader is not TraceBrake itself, so the app turns this straight into a Critical alert.
/// </summary>
public sealed class DecoyReadMessage
{
    public string Kind { get; set; } = SidecarFrame.DecoyRead;
    public long TimestampUnixMs { get; set; }

    /// <summary>The decoy credential file that was read.</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>The process that read it.</summary>
    public int Pid { get; set; }

    /// <summary>The reading process's image path (from the audit event), if available.</summary>
    public string Image { get; set; } = string.Empty;
    /// <summary>"read", "modified", or "deleted".</summary>
    public string Operation { get; set; } = "read";
}

public sealed class DecoyAuditStatusMessage
{
    public string Kind { get; set; } = SidecarFrame.DecoyAuditStatus;
    public long TimestampUnixMs { get; set; }
    public int ExpectedCount { get; set; }
    public int ArmedCount { get; set; }
}

/// <summary>One frame from the elevated sidecar: current process power/wake requests.</summary>
public sealed class WakeRequestsMessage
{
    public string Kind { get; set; } = SidecarFrame.WakeRequests;
    public long TimestampUnixMs { get; set; }
    public bool Available { get; set; }
    public string? Error { get; set; }
    public List<Foreman.Core.Power.WakeRequestEntry> Requests { get; set; } = [];
}
