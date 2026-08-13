using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Foreman.App;

/// <summary>
/// Samples per-process resource usage for the Process Monitor's live view. CPU and I/O are rates,
/// computed from deltas between calls, so Sample() must be invoked on a steady cadence (the window's
/// 2s timer). All reads are best-effort: a process we can't open (gone, or elevated/cross-user at
/// medium integrity) yields zeros rather than throwing.
///
/// Network is deliberately absent — per-process network bytes need an elevated ETW session, which
/// TraceBrake does not run by default.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ResourceSampler : IDisposable
{
    public readonly record struct Metrics(double CpuPercent, long MemoryBytes, double IoBytesPerSec, double? GpuPercent);

    private readonly record struct Snapshot(TimeSpan Cpu, ulong IoBytes, DateTimeOffset At);

    private readonly Dictionary<int, Snapshot> _prev = new();
    private readonly Dictionary<string, PerformanceCounter> _gpuCounters = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _cpuCount = Math.Max(1, Environment.ProcessorCount);
    private bool _gpuAvailable = true;

    public Dictionary<int, Metrics> Sample(IReadOnlyCollection<int> pids)
    {
        var now = DateTimeOffset.UtcNow;
        var result = new Dictionary<int, Metrics>(pids.Count);
        var gpu = ReadGpuByPidGuarded(pids);

        foreach (var pid in pids)
        {
            double cpuPct = 0, ioRate = 0;
            long mem = 0;
            try
            {
                using var p = Process.GetProcessById(pid);
                var cpuTime = p.TotalProcessorTime;
                mem = p.WorkingSet64;
                var ioBytes = ReadIoBytes(p);

                if (_prev.TryGetValue(pid, out var prev))
                {
                    var dt = (now - prev.At).TotalSeconds;
                    if (dt > 0.05)
                    {
                        cpuPct = Math.Clamp((cpuTime - prev.Cpu).TotalSeconds / (dt * _cpuCount) * 100.0, 0, 100);
                        if (ioBytes >= prev.IoBytes)
                            ioRate = (ioBytes - prev.IoBytes) / dt;
                    }
                }
                _prev[pid] = new Snapshot(cpuTime, ioBytes, now);
            }
            catch
            {
                _prev.Remove(pid);   // can't read it this round
            }

            result[pid] = new Metrics(cpuPct, mem, ioRate, gpu.TryGetValue(pid, out var g) ? g : null);
        }

        PrunePrev(pids);
        return result;
    }

    // ── I/O (total transfer bytes: file + device + pipe; not disk-only) ──────────
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessIoCounters(nint hProcess, out IoCounters counters);

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
    }

    private static ulong ReadIoBytes(Process p)
    {
        try
        {
            return GetProcessIoCounters(p.Handle, out var c) ? c.ReadBytes + c.WriteBytes + c.OtherBytes : 0UL;
        }
        catch { return 0UL; }
    }

    // The GPU "GPU Engine" performance counters can HANG indefinitely on some systems (notably certain NVIDIA
    // driver/overlay combinations) — PerformanceCounter has no cancellation. Bound the read with a timeout; if it
    // stalls, permanently disable GPU sampling so CPU/memory/I/O keep flowing. Always runs on the background
    // sampler thread (never the UI), and a stalled read self-disables after one timeout.
    private Dictionary<int, double> ReadGpuByPidGuarded(IReadOnlyCollection<int> pids)
    {
        if (!_gpuAvailable || pids.Count == 0) return new Dictionary<int, double>();
        var task = Task.Run(() => ReadGpuByPid(pids));
        if (task.Wait(TimeSpan.FromSeconds(2)) && task.IsCompletedSuccessfully)
            return task.Result;
        _gpuAvailable = false;   // hung or faulted GPU counters on this box — stop reading them
        return new Dictionary<int, double>();
    }

    // ── GPU (sum of "Utilization Percentage" across the pid's GPU Engine instances) ──
    // Counters are cached and kept alive between samples: a freshly-created counter's first read
    // is a baseline 0, so persistence is what makes the utilization meaningful.
    private Dictionary<int, double> ReadGpuByPid(IReadOnlyCollection<int> pids)
    {
        var map = new Dictionary<int, double>();
        if (!_gpuAvailable || pids.Count == 0) return map;

        try
        {
            if (!PerformanceCounterCategory.Exists("GPU Engine"))
            {
                _gpuAvailable = false;   // VM / no GPU counters — stop trying
                return map;
            }

            var wanted = pids is HashSet<int> hs ? hs : [.. pids];
            var live = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var instance in new PerformanceCounterCategory("GPU Engine").GetInstanceNames())
            {
                var pid = PidFromInstance(instance);
                if (pid is not int p || !wanted.Contains(p)) continue;
                live.Add(instance);
                try
                {
                    if (!_gpuCounters.TryGetValue(instance, out var counter))
                    {
                        counter = new PerformanceCounter("GPU Engine", "Utilization Percentage", instance, readOnly: true);
                        _gpuCounters[instance] = counter;
                    }
                    map[p] = map.GetValueOrDefault(p) + counter.NextValue();
                }
                catch { /* this engine instance vanished mid-read */ }
            }

            // dispose counters for instances that are gone
            foreach (var dead in _gpuCounters.Keys.Where(k => !live.Contains(k)).ToList())
            {
                _gpuCounters[dead].Dispose();
                _gpuCounters.Remove(dead);
            }
        }
        catch { /* perf-counter subsystem unavailable */ }

        return map;
    }

    // "pid_1234_luid_0x..._engtype_3D" → 1234
    private static int? PidFromInstance(string instance)
    {
        if (!instance.StartsWith("pid_", StringComparison.Ordinal)) return null;
        var end = instance.IndexOf('_', 4);
        if (end < 0) return null;
        return int.TryParse(instance.AsSpan(4, end - 4), out var pid) ? pid : null;
    }

    private void PrunePrev(IReadOnlyCollection<int> pids)
    {
        if (_prev.Count <= pids.Count * 2 + 16) return;
        var keep = pids is HashSet<int> hs ? hs : [.. pids];
        foreach (var stale in _prev.Keys.Where(k => !keep.Contains(k)).ToList())
            _prev.Remove(stale);
    }

    public void Dispose()
    {
        foreach (var c in _gpuCounters.Values) c.Dispose();
        _gpuCounters.Clear();
    }
}
