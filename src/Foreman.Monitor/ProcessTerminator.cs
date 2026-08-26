using System.Diagnostics;

namespace Foreman.Monitor;

/// <summary>
/// The live-OS identity check and termination are one operation so callers cannot accidentally validate only a
/// stale tracker record. The path predicate runs against the live process image immediately before termination.
/// </summary>
public interface IProcessTerminator
{
    bool TryTerminate(
        int pid,
        DateTimeOffset expectedStartTime,
        bool entireProcessTree,
        Func<string?, bool> isProtectedExecutable);
}

internal sealed class SystemProcessTerminator : IProcessTerminator
{
    public bool TryTerminate(
        int pid,
        DateTimeOffset expectedStartTime,
        bool entireProcessTree,
        Func<string?, bool> isProtectedExecutable)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            var liveStart = new DateTimeOffset(process.StartTime).ToUniversalTime();
            if (Math.Abs((liveStart - expectedStartTime.ToUniversalTime()).TotalSeconds) > 1) return false;

            string? livePath;
            try { livePath = process.MainModule?.FileName; }
            catch { livePath = null; }
            if (isProtectedExecutable(livePath)) return false;

            process.Kill(entireProcessTree);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
