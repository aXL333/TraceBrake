using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Foreman.Core.Security;
using Microsoft.Win32.SafeHandles;

namespace Foreman.App;

/// <summary>
/// Detects launch-context filesystem redirection of TraceBrake's data directory (the split-brain canary — see
/// <see cref="DataDirRedirection"/> for why this matters). Opens a throwaway probe file in the data dir and
/// asks the kernel for the handle's FINAL path: a sandbox/container overlay can virtualize the path Foreman
/// asks for, but it cannot lie about where the handle actually landed. Best-effort — any failure returns
/// "not redirected" rather than blocking startup or crying wolf.
/// </summary>
internal static class DataDirRedirectionProbe
{
    private const string ProbeFileName = ".redirect-probe";

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    /// <summary>
    /// The directory the OS ACTUALLY resolves <paramref name="dataDir"/> into when that differs from the
    /// requested path; null when not redirected or when the probe couldn't tell.
    /// </summary>
    public static string? DetectRedirect(string dataDir)
    {
        try
        {
            Directory.CreateDirectory(dataDir);
            var probePath = Path.Combine(dataDir, ProbeFileName);
            string finalPath;
            using (var fs = new FileStream(probePath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
                                           FileShare.ReadWrite | FileShare.Delete))
            {
                finalPath = GetFinalPath(fs.SafeFileHandle);
            }
            try { File.Delete(probePath); } catch { /* leftover probe file is harmless */ }

            if (finalPath.Length == 0) return null;
            var actualDir = Path.GetDirectoryName(DataDirRedirection.NormalizeFinalPath(finalPath));
            return actualDir is { Length: > 0 } && DataDirRedirection.IsRedirected(dataDir, actualDir)
                ? actualDir
                : null;
        }
        catch { return null; }   // a failed probe is "unknown", never an alarm
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var buf = new StringBuilder(1024);
        var n = GetFinalPathNameByHandle(handle, buf, (uint)buf.Capacity, 0);
        if (n > buf.Capacity)   // returned length includes what didn't fit — retry once, correctly sized
        {
            buf = new StringBuilder((int)n + 1);
            n = GetFinalPathNameByHandle(handle, buf, (uint)buf.Capacity, 0);
        }
        return n == 0 || n > buf.Capacity ? string.Empty : buf.ToString(0, (int)n);
    }
}
