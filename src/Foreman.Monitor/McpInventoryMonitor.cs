using System.Text.Json;
using Foreman.Core.Events;
using Foreman.Core.Mcp;
using Foreman.Core.Models;

namespace Foreman.Monitor;

/// <summary>
/// Tier 0: watches the MCP servers configured across AI harnesses and raises a Medium alert when a
/// new (or changed-target) server appears — supply-chain / "who added this MCP server?" detection.
/// Config-file reads only (no network, no elevation). The seen-set is persisted so only genuinely
/// new servers alert across restarts; the very first run establishes a silent baseline, and the first
/// time a NEW config source appears (e.g. Codex's config.toml parsed for the first time after an
/// update) its servers are baselined silently rather than flooding the user with alerts.
/// </summary>
public sealed class McpInventoryMonitor : IDisposable
{
    private readonly EventBus _bus;
    private readonly int _ownPort;
    private readonly Func<List<McpServerEntry>> _scan;
    private readonly string _seenFile;
    private readonly string _sourcesFile;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _seenSources = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private Timer? _timer;
    private volatile IReadOnlyList<McpServerEntry> _current = [];

    public McpInventoryMonitor(EventBus bus, int ownPort, string? baseDir = null, Func<List<McpServerEntry>>? scan = null)
    {
        _bus = bus;
        _ownPort = ownPort;
        _scan = scan ?? McpInventoryScanner.Scan;
        var dir = baseDir ?? Foreman.Core.ProductIdentity.LocalDataRoot;
        _seenFile    = Path.Combine(dir, "mcp-seen.json");
        _sourcesFile = Path.Combine(dir, "mcp-seen-sources.json");
    }

    public IReadOnlyList<McpServerEntry> Current => _current;

    public void Start()
    {
        var firstRun = !File.Exists(_seenFile);
        LoadSeen();
        Scan(firstRun);   // baseline silently on the very first run; alert on new thereafter
        _timer = new Timer(_ => Scan(firstRun: false), null, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60));
    }

    /// <summary>Runs one inventory pass now (manual refresh; also the test seam).</summary>
    public void ScanNow() => Scan(firstRun: false);

    private void Scan(bool firstRun)
    {
        List<McpServerEntry> found;
        try { found = _scan(); }
        catch { return; }
        _current = found;

        lock (_lock)
        {
            var seenBefore    = _seen.Count;
            var sourcesBefore = _seenSources.Count;

            var newOnes = ClassifyNewServers(found, _seen, _seenSources, firstRun);

            if (_seen.Count != seenBefore || _seenSources.Count != sourcesBefore)
                SaveSeen();

            foreach (var entry in newOnes)
            {
                if (IsForemanSelfServer(entry, _ownPort))
                {
                    _bus.Publish(new InfoEvent(
                        DateTimeOffset.UtcNow,
                        "Foreman.McpInventory",
                        $"TraceBrake MCP connector registered for {entry.Harness}: {Trunc(entry.Target, 100)}"));
                    continue;
                }

                _bus.Publish(new MonitoringNoticeEvent(
                    DateTimeOffset.UtcNow,
                    ForemanSeverity.Medium,
                    "Foreman.McpInventory",
                    $"New MCP server '{entry.Name}' ({entry.Transport}) configured for {entry.Harness}: {Trunc(entry.Target, 100)}"));
            }
        }
    }

    /// <summary>
    /// Decides which discovered servers are genuinely new and worth a Medium alert. A server alerts only
    /// when its key is new AND its config source was already baselined (and it isn't the first run). The
    /// first time a SOURCE is seen, all its servers are baselined SILENTLY. Mutates <paramref name="seenKeys"/>
    /// and <paramref name="seenSources"/> to record what was seen. Unit-tested without the EventBus.
    /// </summary>
    public static List<McpServerEntry> ClassifyNewServers(
        IReadOnlyList<McpServerEntry> found,
        ISet<string> seenKeys,
        ISet<string> seenSources,
        bool firstRun)
    {
        var newOnes = new List<McpServerEntry>();
        foreach (var entry in found)
        {
            var sourceKnown = seenSources.Contains(entry.SourceFile);
            var keyIsNew    = seenKeys.Add(entry.Key);
            if (keyIsNew && !firstRun && sourceKnown)
                newOnes.Add(entry);
        }

        // Record every source now seen — this silently baselines the first sighting of each source.
        foreach (var entry in found)
            seenSources.Add(entry.SourceFile);

        return newOnes;
    }

    /// <summary>
    /// True only for TraceBrake's OWN local MCP endpoint — name "foreman", http/sse, loopback, the
    /// configured port, path "/mcp". Pinning the port (mirrors McpToolScanMonitor.IsScannableTarget)
    /// narrows the window where a config-writing attacker could name a server "foreman" on some other
    /// loopback port to demote the supply-chain alert to a silent Info.
    /// </summary>
    public static bool IsForemanSelfServer(McpServerEntry entry, int ownPort)
    {
        if (!string.Equals(entry.Name, "foreman", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!string.Equals(entry.Transport, "http", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(entry.Transport, "sse", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!Uri.TryCreate(entry.Target, UriKind.Absolute, out var uri))
            return false;
        if (!uri.IsLoopback)
            return false;
        if (uri.Port != ownPort)
            return false;

        var path = uri.AbsolutePath.TrimEnd('/');
        return string.Equals(path, "/mcp", StringComparison.OrdinalIgnoreCase);
    }

    private void LoadSeen()
    {
        LoadSet(_seenFile, _seen);
        LoadSet(_sourcesFile, _seenSources);
    }

    private static void LoadSet(string file, HashSet<string> set)
    {
        try
        {
            if (!File.Exists(file)) return;
            var items = JsonSerializer.Deserialize<string[]>(File.ReadAllText(file));
            if (items is not null)
                foreach (var i in items) set.Add(i);
        }
        catch { /* corrupt file — treat as empty */ }
    }

    private void SaveSeen()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_seenFile)!);
            File.WriteAllText(_seenFile,    JsonSerializer.Serialize(_seen.ToArray()));
            File.WriteAllText(_sourcesFile, JsonSerializer.Serialize(_seenSources.ToArray()));
        }
        catch { /* best-effort */ }
    }

    private static string Trunc(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    public void Dispose() => _timer?.Dispose();
}
