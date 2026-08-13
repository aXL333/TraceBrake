using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Foreman.Core.Notifications;

namespace Foreman.Guardian;

/// <summary>
/// Installs / uninstalls the guardian as a LocalSystem Windows service (circle-back Phase A, the privilege
/// boundary). Runs ELEVATED (the app launches it with runas). Steps, in order, idempotent + rolled back on failure:
///   1. LPE guard — verify this binary is the genuine same-publisher TraceBrake before it can become SYSTEM.
///   2. Copy the guardian payload to %ProgramFiles%\Foreman\guardian (NOT user-writable).
///   3. ACL it: SYSTEM + Administrators full, Users read+execute (no write) — the agent can't tamper the binary.
///   4. Create + ACL %ProgramData%\Foreman\guardian as SYSTEM/Admins only (no interactive user) for SYSTEM state.
///   5. CreateService LocalSystem, auto-start (Win32 — no sc.exe quoting pitfalls).
///   6. Register the OS event-log source.
///   7. Start it.
/// Uninstall is presence-gated by the caller; here it just stops → deletes the service → removes the dirs.
///
/// The path/gate logic is pure + testable; the privileged execution (CreateService, ACLs, ProgramFiles writes)
/// can only be validated by an actual elevated run.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class GuardianInstaller
{
    public const string ServiceName = "Foreman.Guardian";
    public const string DisplayName = "TraceBrake Guardian";

    public static string ProgramFilesDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Foreman", "guardian");
    public static string ProgramDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Foreman", "guardian");
    public static string InstalledExePath => Path.Combine(ProgramFilesDir, "Foreman.Guardian.exe");

    public static int Install(int? foremanPid, Action<string> log)
    {
        if (!GuardianInstallReference.TryResolve(foremanPid, Environment.ProcessPath, out var foremanPath, out var referenceReason))
        {
            log($"install REFUSED (launcher): {referenceReason}");
            return 2;
        }

        // 1. LPE guard — refuse to register a binary that isn't the genuine, same-publisher TraceBrake as SYSTEM.
        string? recordedInstallRoot;
        try { recordedInstallRoot = GuardianInstallRoot.Read(); }
        catch (Exception ex) { log($"install REFUSED (root anchor): {ex.Message}"); return 2; }

        var (trusted, reason) = GuardianIntegrity.VerifyForInstall(
            foremanPath, Environment.ProcessPath, recordedInstallRoot);
        if (!trusted) { log($"install REFUSED (integrity): {reason}"); return 2; }
        log($"integrity ok: {reason}");

        GuardianClientPolicy policy;
        try
        {
            policy = GuardianClientPolicy.CreateForInstall(foremanPath);
            var priorPolicyPath = GuardianClientPolicy.PolicyPath(ProgramDataDir);
            if (File.Exists(priorPolicyPath))
            {
                var priorPolicy = GuardianClientPolicy.Load(ProgramDataDir);
                var replacement = GuardianClientPolicy.CanReplace(priorPolicy, policy);
                if (!replacement.Allowed)
                {
                    log($"install REFUSED (client policy): {replacement.Reason}");
                    return 2;
                }
            }
            log(policy.PublisherAuthenticated
                ? "client policy: verified publisher pin."
                : "client policy: unsigned development path + SHA-256 pin (not publisher authenticated).");
        }
        catch (Exception ex)
        {
            log($"install REFUSED (client policy): {ex.Message}");
            return 2;
        }

        var srcDir = Path.GetDirectoryName(Environment.ProcessPath)!;
        var parent = Directory.GetParent(ProgramFilesDir)?.FullName
                     ?? throw new InvalidOperationException("Guardian install parent is unavailable.");
        var stageDir = Path.Combine(parent, $"guardian.stage.{Guid.NewGuid():N}");
        var backupDir = Path.Combine(parent, $"guardian.backup.{Guid.NewGuid():N}");
        var hadPayload = Directory.Exists(ProgramFilesDir);
        var serviceExisted = ServiceExists();
        byte[]? policyBackup;
        try { policyBackup = GuardianClientPolicy.CaptureRaw(ProgramDataDir); }
        catch (Exception ex) { log($"install REFUSED (policy backup): {ex.Message}"); return 2; }
        try
        {
            CopyTree(srcDir, stageDir, log);                 // stage before interrupting a working service
            HardenDir(stageDir, allowUsersReadExecute: true);
            HardenDir(ProgramDataDir, allowUsersReadExecute: false);   // 4 (SYSTEM/Admins only)
            policy.Save(ProgramDataDir);

            if (serviceExisted) StopService(log);
            if (hadPayload) Directory.Move(ProgramFilesDir, backupDir);
            Directory.Move(stageDir, ProgramFilesDir);
            CreateService(InstalledExePath, log);            // 5
            TryRegisterEventSource(log);                     // 6
            StartService(log);                               // 7
            GuardianInstallRoot.Write(GuardianInstallRoot.RootForExecutable(foremanPath));
            TryDeleteDir(backupDir, log);

            log("guardian installed and started.");
            return 0;
        }
        catch (Exception ex)
        {
            log($"install FAILED: {ex.Message} — restoring the previous installation.");
            TryDeleteDir(stageDir, log);
            if (serviceExisted)
            {
                try { StopService(log); } catch { /* it may never have restarted */ }
            }
            else
            {
                try { StopAndDeleteService(log); } catch { }
            }

            try { GuardianClientPolicy.RestoreRaw(ProgramDataDir, policyBackup); }
            catch (Exception policyEx) { log($"client-policy restore failed: {policyEx.Message}"); }

            try
            {
                if (Directory.Exists(backupDir))
                {
                    TryDeleteDir(ProgramFilesDir, log);
                    if (Directory.Exists(ProgramFilesDir))
                        throw new IOException("Could not remove the failed replacement payload.");
                    Directory.Move(backupDir, ProgramFilesDir);
                    log("previous guardian payload restored.");
                }
                else if (!hadPayload)
                {
                    TryDeleteDir(ProgramFilesDir, log);
                }
            }
            catch (Exception restoreEx)
            {
                log($"previous payload restore failed: {restoreEx.Message}; backup remains at {backupDir}");
            }

            try { GuardianInstallRoot.Restore(recordedInstallRoot); }
            catch (Exception rootEx) { log($"install-root restore failed: {rootEx.Message}"); }

            if (serviceExisted)
                try { StartService(log); } catch (Exception restartEx) { log($"previous service restart failed: {restartEx.Message}"); }
            return 4;
        }
    }

    public static int Uninstall(Action<string> log)
    {
        try
        {
            StopAndDeleteService(log);
            TryDeleteDir(ProgramFilesDir, log);
            TryDeleteDir(ProgramDataDir, log);
            GuardianInstallRoot.Restore(priorRoot: null);
            log("guardian uninstalled.");
            return 0;
        }
        catch (Exception ex)
        {
            log($"uninstall error: {ex.Message}");
            return 4;
        }
    }

    // ── filesystem ───────────────────────────────────────────────────────────────────────────────────
    private static void CopyTree(string src, string dst, Action<string> log)
    {
        src = Path.GetFullPath(src);
        dst = Path.GetFullPath(dst);
        if ((File.GetAttributes(src) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Guardian source directory cannot be a reparse point.");

        Directory.CreateDirectory(dst);
        var pending = new Queue<string>();
        pending.Enqueue(src);
        while (pending.Count > 0)
        {
            var current = pending.Dequeue();
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException($"Guardian payload contains a reparse point: {entry}");

                var target = SafeTargetPath(src, dst, entry);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    Directory.CreateDirectory(target);
                    pending.Enqueue(entry);
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    File.Copy(entry, target, overwrite: false);
                }
            }
        }
        log($"copied guardian payload → {dst}");
    }

    internal static string SafeTargetPath(string sourceRoot, string destinationRoot, string sourceEntry)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(sourceRoot), Path.GetFullPath(sourceEntry));
        if (relative == ".." || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            throw new InvalidDataException("Guardian payload entry escapes its source root.");

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(destinationRoot)) + Path.DirectorySeparatorChar;
        var target = Path.GetFullPath(Path.Combine(root, relative));
        if (!target.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Guardian payload entry escapes its destination root.");
        return target;
    }

    private static void HardenDir(string dir, bool allowUsersReadExecute)
    {
        Directory.CreateDirectory(dir);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);   // drop inherited (user) ACEs
        sec.SetOwner(admins);
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (allowUsersReadExecute)
            sec.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));

        new DirectoryInfo(dir).SetAccessControl(sec);
    }

    private static void TryDeleteDir(string dir, Action<string> log)
    {
        try { if (Directory.Exists(dir)) { Directory.Delete(dir, recursive: true); log($"removed {dir}"); } }
        catch (Exception ex) { log($"could not remove {dir}: {ex.Message}"); }
    }

    private static void TryRegisterEventSource(Action<string> log)
    {
        try
        {
            if (!System.Diagnostics.EventLog.SourceExists(OsEventLogNames.SourceName))
            {
                System.Diagnostics.EventLog.CreateEventSource(
                    new System.Diagnostics.EventSourceCreationData(OsEventLogNames.SourceName, OsEventLogNames.LogName));
                log("registered OS event-log source.");
            }
        }
        catch (Exception ex) { log($"event-source registration skipped: {ex.Message}"); }
    }

    // ── Win32 service control (advapi32) ──────────────────────────────────────────────────────────────
    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F, SERVICE_ALL_ACCESS = 0xF01FF;
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x10, SERVICE_AUTO_START = 0x2, SERVICE_ERROR_NORMAL = 0x1;
    private const uint SERVICE_CONTROL_STOP = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machine, string? db, uint access);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(IntPtr scm, string name, string display, uint access, uint type,
        uint start, uint error, string binPath, string? group, IntPtr tagId, string? deps, string? user, string? pwd);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartService(IntPtr svc, uint argc, string[]? argv);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr svc, uint control, ref SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr svc, ref SERVICE_STATUS status);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr svc);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr h);

    private const int ERROR_SERVICE_EXISTS = 1073;

    private static bool ServiceExists()
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            var svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) return false;
            CloseServiceHandle(svc);
            return true;
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void CreateService(string exePath, Action<string> log)
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            // binPath stored verbatim by SCM (no shell) — quote the exe (Program Files has a space) + the verb.
            var binPath = $"\"{exePath}\" --service";
            var svc = CreateService(scm, ServiceName, DisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binPath, null, IntPtr.Zero, null, null /*=LocalSystem*/, null);
            if (svc == IntPtr.Zero)
            {
                var err = Marshal.GetLastWin32Error();
                if (err == ERROR_SERVICE_EXISTS) { log("service already exists — reusing."); return; }
                throw new Win32Exception(err, "CreateService failed");
            }
            CloseServiceHandle(svc);
            log("service created (LocalSystem, auto-start).");
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StartService(Action<string> log)
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            var svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenService failed");
            try
            {
                if (!StartService(svc, 0, null))
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err == 1056) log("service already running."); // ERROR_SERVICE_ALREADY_RUNNING
                    else throw new Win32Exception(err, "Starting the guardian service failed");
                }
                else log("service started.");
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StopService(Action<string> log)
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            var svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) return;
            try
            {
                var status = new SERVICE_STATUS();
                if (!ControlService(svc, SERVICE_CONTROL_STOP, ref status))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != 1062) throw new Win32Exception(error, "Stopping the existing guardian failed");
                }
                var deadline = DateTime.UtcNow.AddSeconds(15);
                while (DateTime.UtcNow < deadline)
                {
                    if (!QueryServiceStatus(svc, ref status))
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryServiceStatus failed");
                    if (status.CurrentState == 1) break; // SERVICE_STOPPED
                    Thread.Sleep(200);
                }
                if (status.CurrentState != 1)
                    throw new TimeoutException("The existing guardian did not stop within 15 seconds.");
                log("existing service stopped for upgrade.");
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    private static void StopAndDeleteService(Action<string> log)
    {
        if (ServiceExists()) StopService(log);
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            var svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc == IntPtr.Zero) { log("service not present."); return; }
            try
            {
                if (!DeleteService(svc)) log($"DeleteService returned {Marshal.GetLastWin32Error()}.");
                else log("service deleted.");
            }
            finally { CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }
}
