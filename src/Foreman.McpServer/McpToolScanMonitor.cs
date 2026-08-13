using System.Text.Json;
using Foreman.Core.Events;
using Foreman.Core.Mcp;
using Foreman.Core.Models;

namespace Foreman.McpServer;

/// <summary>
/// Tier 1 (opt-in): periodically connects to the HTTP/SSE MCP servers the user's harnesses are
/// configured to use, enumerates their tools, and runs <see cref="McpToolScanner"/> over the tool
/// names + descriptions to surface prompt-injection / exfil text smuggled into tool docs.
///
/// This is the ONLY component that makes outbound connections to third-party servers, so it is OFF
/// unless the user enables it (Settings → Scan MCP tools). stdio servers are never launched — Foreman
/// won't spawn the process it's auditing — and TraceBrake's own server is skipped. Findings are
/// persisted-deduped so the same finding doesn't re-alert on every pass.
/// </summary>
public sealed class McpToolScanMonitor : IDisposable
{
    private static readonly TimeSpan ScanInterval     = TimeSpan.FromHours(6);
    private static readonly TimeSpan PerServerTimeout = TimeSpan.FromSeconds(15);

    private readonly EventBus _bus;
    private readonly Func<IEnumerable<McpServerEntry>> _inventory;
    private readonly int _ownPort;
    private readonly string _seenFile;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly McpToolProbe _probe = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _lock = new();
    private Timer? _timer;
    private volatile IReadOnlyList<McpToolFinding> _current = [];
    private volatile string _lastSummary = "MCP tool scan has not run yet.";

    public McpToolScanMonitor(EventBus bus, Func<IEnumerable<McpServerEntry>> inventory, int ownPort, string? baseDir = null)
    {
        _bus       = bus;
        _inventory = inventory;
        _ownPort   = ownPort;
        var dir    = baseDir ?? Foreman.Core.ProductIdentity.LocalDataRoot;
        _seenFile  = Path.Combine(dir, "mcp-tool-findings-seen.json");
    }

    public IReadOnlyList<McpToolFinding> Current => _current;
    public string LastSummary => _lastSummary;
    public bool IsRunning => _timer is not null;

    public void Start()
    {
        if (_timer is not null) return;       // already running
        LoadSeen();
        // initial scan shortly after enable, then on a slow cadence to catch description drift
        _timer = new Timer(_ => _ = ScanNowAsync(), null, TimeSpan.FromSeconds(5), ScanInterval);
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    /// <summary>Runs one scan pass now. Overlapping calls are coalesced (returns the in-flight result).</summary>
    public async Task<IReadOnlyList<McpToolFinding>> ScanNowAsync(CancellationToken ct = default)
    {
        if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
            return _current;                   // a scan is already in flight

        try
        {
            var snapshot = _inventory().ToList();
            var targets  = snapshot
                .Where(IsScannable)
                .GroupBy(e => e.Target, StringComparer.OrdinalIgnoreCase)   // one probe per distinct endpoint
                .Select(g => g.First())
                .ToList();

            var findings = new List<McpToolFinding>();
            int scanned = 0, unreachable = 0;
            foreach (var server in targets)
            {
                try
                {
                    findings.AddRange(await _probe.ProbeAsync(server, PerServerTimeout, ct).ConfigureAwait(false));
                    scanned++;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch { unreachable++; }        // needs its own auth / offline / not an MCP endpoint
            }

            // Name what was skipped and why, so "1 skipped" isn't a mystery (it's usually TraceBrake itself).
            var skipped = snapshot
                .Where(e => !IsScannable(e))
                .Select(e => $"{e.Name} ({SkipReason(e)})")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            _current = findings;
            PublishNew(findings);
            var probed = scanned + unreachable;
            _lastSummary =
                $"Checked {probed} HTTP MCP server(s): {scanned} reachable, {unreachable} unreachable, " +
                $"{findings.Count} finding(s)" +
                (skipped.Count > 0 ? $"; skipped {skipped.Count}: {string.Join(", ", skipped)}" : "") + ".";
            _bus.Publish(new MonitoringNoticeEvent(
                DateTimeOffset.UtcNow, ForemanSeverity.Info, "Foreman.McpToolScan", _lastSummary));
            return findings;
        }
        finally { _gate.Release(); }
    }

    private bool IsScannable(McpServerEntry e) => IsScannableTarget(e.Target, _ownPort);

    // Why a server was skipped — for the human-readable scan summary.
    private string SkipReason(McpServerEntry e)
    {
        if (!Uri.TryCreate(e.Target, UriKind.Absolute, out var u)) return "stdio";
        if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) return "non-http";
        var isLocal = u.IsLoopback || string.Equals(u.Host, "localhost", StringComparison.OrdinalIgnoreCase);
        if (isLocal && u.Port == _ownPort) return "self";
        return "skipped";
    }

    /// <summary>
    /// True if a server target is something we'll probe: an absolute http(s) URL that isn't TraceBrake's
    /// own loopback server. stdio (command-based, no URL) and self are excluded.
    /// </summary>
    public static bool IsScannableTarget(string target, int ownPort)
    {
        if (!Uri.TryCreate(target, UriKind.Absolute, out var u)) return false;            // stdio / no URL
        if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) return false;
        var isLocal = u.IsLoopback || string.Equals(u.Host, "localhost", StringComparison.OrdinalIgnoreCase);
        if (isLocal && u.Port == ownPort) return false;                                    // TraceBrake's own server
        return true;
    }

    private void PublishNew(IReadOnlyList<McpToolFinding> findings)
    {
        lock (_lock)
        {
            var fresh = new List<McpToolFinding>();
            foreach (var f in findings)
                if (_seen.Add($"{f.Server}|{f.Tool}|{f.Signal}"))
                    fresh.Add(f);

            if (fresh.Count > 0) SaveSeen();

            foreach (var f in fresh)
                _bus.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow, ForemanSeverity.High, "Foreman.McpToolScan",
                    $"MCP tool '{f.Tool}' on server '{f.Server}' contains suspicious text [{f.Signal}]: {Trunc(f.Excerpt, 120)}"));
        }
    }

    private void LoadSeen()
    {
        try
        {
            if (!File.Exists(_seenFile)) return;
            var keys = JsonSerializer.Deserialize<string[]>(File.ReadAllText(_seenFile));
            if (keys is not null)
                foreach (var k in keys) _seen.Add(k);
        }
        catch { /* corrupt seen-file — treat as empty */ }
    }

    private void SaveSeen()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_seenFile)!);
            File.WriteAllText(_seenFile, JsonSerializer.Serialize(_seen.ToArray()));
        }
        catch { /* best-effort */ }
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    public void Dispose()
    {
        _timer?.Dispose();
        _gate.Dispose();
    }
}
