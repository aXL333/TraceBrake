namespace Foreman.Core.Security;

/// <summary>
/// Pure decision logic for the launch-context redirection canary. Some launch environments (agent-harness
/// sandboxes, packaged-app containers) transparently redirect file I/O under user-profile paths into a private
/// overlay — e.g. processes spawned from inside a packaged desktop app can have <c>%LOCALAPPDATA%</c> writes
/// land in that package's <c>LocalCache</c> directory. A TraceBrake launched that way reads and writes a COPY of
/// its state (settings, vault, event log, tokens) divorced from the real install's, which silently splits the
/// security posture across two stores and makes the external rollback witness cry wolf on every flip between
/// the two lineages (each chain is missing the other's externally-witnessed heads).
///
/// The App probes this by opening a file in its data directory and asking the kernel for the handle's FINAL
/// path (<c>GetFinalPathNameByHandle</c> — the one thing an overlay can't hide); this class normalizes that
/// answer, decides whether it means redirection, and words the operator notice. Pure string logic, fully
/// testable; the P/Invoke lives App-side.
/// </summary>
public static class DataDirRedirection
{
    /// <summary>
    /// Strips the Win32 prefixes <c>GetFinalPathNameByHandle</c> returns (<c>\\?\C:\…</c> → <c>C:\…</c>,
    /// <c>\\?\UNC\server\share</c> → <c>\\server\share</c>) so the final path compares against normal paths.
    /// </summary>
    public static string NormalizeFinalPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + path[@"\\?\UNC\".Length..];
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
            return path[@"\\?\".Length..];
        return path;
    }

    /// <summary>
    /// True when the kernel resolved the probe into a DIFFERENT directory than the one TraceBrake asked for.
    /// Comparison is case-insensitive (Windows paths) and tolerant of trailing separators; an empty/unknown
    /// final directory is NOT redirection (the probe couldn't tell — never alarm on a failed probe).
    /// </summary>
    public static bool IsRedirected(string requestedDir, string finalDir)
    {
        if (string.IsNullOrWhiteSpace(requestedDir) || string.IsNullOrWhiteSpace(finalDir)) return false;
        return !string.Equals(Trim(requestedDir), Trim(NormalizeFinalPath(finalDir)), StringComparison.OrdinalIgnoreCase);

        static string Trim(string p) => p.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    /// <summary>The operator-facing notice: name both paths, say what it means, say what to do.</summary>
    public static string BuildNotice(string requestedDir, string actualDir) =>
        $"TraceBrake's data directory is being redirected by the launch environment: it asked for '{requestedDir}' " +
        $"but the OS is actually reading and writing '{actualDir}'. This instance is operating on a sandboxed " +
        "COPY of TraceBrake's state (settings, vault, event log, tokens) — changes made here will NOT be visible " +
        "to a normally-launched Foreman, and the event-log rollback witness will disagree across the two. This " +
        "typically means TraceBrake was started from inside a sandboxed/containerized app (e.g. an AI-agent session). " +
        "Close this instance and start TraceBrake from the tray, Explorer, or its shortcut instead.";
}
