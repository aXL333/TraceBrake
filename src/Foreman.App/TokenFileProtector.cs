using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Foreman.App;

/// <summary>
/// Locks the MCP token file down to the current user only.
///
/// The token gates the MCP endpoint, but the file is created under %LocalAppData%\TraceBrake and
/// would otherwise inherit that directory's ACL — which on some machines (e.g. sandbox setups)
/// grants other principals read access, defeating the gate. Re-owning the file to the current
/// user and removing inherited ACEs means only same-user processes can read the token.
/// (A same-user process can still read it — that is the OS trust boundary, by design.)
/// </summary>
[SupportedOSPlatform("windows")]
internal static class TokenFileProtector
{
    public static void RestrictToCurrentUser(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (identity.User is not { } owner) return;

            var security = new FileSecurity();
            security.SetOwner(owner);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false); // drop inherited ACEs
            security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
        catch { /* best-effort hardening — never block startup over an ACL tweak */ }
    }
}
