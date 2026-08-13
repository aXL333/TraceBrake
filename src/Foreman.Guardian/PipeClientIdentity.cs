using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Foreman.Guardian;

/// <summary>
/// Resolves the image path of the process on the other end of a named-pipe connection, so the guardian can
/// Authenticode-verify its caller (only the real, same-publisher TraceBrake may request a seal). Best-effort: any
/// failure returns null, which the caller treats as "can't confirm" (rejected on signed builds, allowed on dev).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PipeClientIdentity
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle Pipe, out uint ClientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    public static string? GetClientImagePath(NamedPipeServerStream server)
    {
        try
        {
            if (!GetNamedPipeClientProcessId(server.SafePipeHandle, out var pid)) return null;
            using var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h.IsInvalid) return null;
            var buf = new StringBuilder(1024);
            var size = (uint)buf.Capacity;
            return QueryFullProcessImageNameW(h, 0, buf, ref size) ? buf.ToString() : null;
        }
        catch
        {
            return null;
        }
    }
}
