using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;
using Foreman.Core.Ipc;
using Foreman.Core.Security;

namespace Foreman.EtwSidecar;

/// <summary>
/// Elevated decoy read-auditing. Places a SACL audit ACE (audit successful ReadData by Everyone) on each
/// decoy credential file, enables the Windows "Audit File System" subcategory if it isn't already on, and
/// tails the Security log for Event 4663 (object access). Any read of a tracked decoy by a process other
/// than TraceBrake becomes a <see cref="DecoyReadMessage"/> the sidecar streams to the app.
///
/// All of this needs admin (the sidecar is the only elevated component). Cleanup is exact: it removes only the
/// audit ACEs it owns — the ones it added this run, plus any identical Everyone/ReadData/Success ACE it adopted
/// from a prior run that crashed before cleanup (its own signature on its own decoy) — and reverts the audit
/// subcategory ONLY if it was the one to enable it, so a policy the user already had is never touched. A broader
/// pre-existing rule is never adopted or stripped. Everything is wrapped so a failure degrades to "no decoy
/// auditing" rather than throwing.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class DecoyAudit : IDisposable
{
    private readonly string[] _decoyPaths;
    private readonly int[] _excludedPids;
    private readonly ConcurrentQueue<DecoyReadMessage> _hits = new();
    private readonly DecoyAuditEventCorrelator _correlator;
    private readonly List<string> _sacled = [];
    private EventLogWatcher? _watcher;
    private bool _weEnabledAuditPol;
    private readonly string _auditPolInstanceId = Guid.NewGuid().ToString("N");
    private DateTimeOffset _lastMarkerRefresh = DateTimeOffset.MinValue;
    private static readonly TimeSpan MarkerRefreshInterval = TimeSpan.FromMinutes(1);

    public DecoyAudit(IEnumerable<string> decoyPaths, IEnumerable<int> excludedPids)
    {
        _decoyPaths = decoyPaths.Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        _excludedPids = excludedPids.ToArray();
        _correlator = new DecoyAuditEventCorrelator(_decoyPaths, _excludedPids);
    }

    public int ExpectedCount => _decoyPaths.Length;
    public int ArmedCount => _sacled.Count;

    public bool Start()
    {
        if (_decoyPaths.Length == 0) return false;
        try
        {
            EnablePrivilege("SeSecurityPrivilege");
            foreach (var p in _decoyPaths)
                if (EnsureAuditAce(p)) _sacled.Add(p);
            // _sacled now holds every path we are actually auditing — ones we newly SACL'd AND ones that already
            // carried our exact ACE from a prior run that crashed before Cleanup. If it is empty, every decoy is
            // missing or unwritable, so there is nothing to watch. (The old gate keyed off only NEWLY-added ACEs,
            // so a full set of crash-orphaned ACEs left the watcher un-started while the app still showed
            // "connected" — a silently dead tripwire.)
            if (_sacled.Count == 0) return false;
            // Persist auditpol ownership across restarts: if a prior run enabled the "File System" success
            // subcategory and then crashed/was killed before Cleanup, its in-memory ownership flag was lost and
            // the policy would sit orphaned-on with no one to revert it. A machine-wide marker lets this run
            // reclaim that ownership and revert it on clean teardown.
            AcquireAuditPolicyOwnership();
            StartWatcher();
            return true;
        }
        catch { Cleanup(); return false; }
    }

    /// <summary>Pulls any decoy reads observed since the last call (the pipe-writer loop drains this).</summary>
    public IReadOnlyList<DecoyReadMessage> Drain()
    {
        RefreshAuditPolicyLeaseIfDue();
        var list = new List<DecoyReadMessage>();
        while (_hits.TryDequeue(out var m)) list.Add(m);
        return list;
    }

    private void StartWatcher()
    {
        var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4663 or EventID=4660)]]");
        _watcher = new EventLogWatcher(query);
        _watcher.EventRecordWritten += OnEvent;
        _watcher.Enabled = true;
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;
        try
        {
            var parsed = ParseAccessEvent(e.EventRecord.ToXml());
            foreach (var hit in _correlator.Process(parsed))
                _hits.Enqueue(hit);
        }
        catch { /* one bad event — ignore */ }
        finally { try { e.EventRecord.Dispose(); } catch { } }
    }

    // 4663 EventData carries ObjectName, ProcessId (hex), ProcessName (accessing image).
    private static DecoyAuditAccessEvent ParseAccessEvent(string xml)
    {
        var doc = XDocument.Parse(xml);
        XNamespace ns = doc.Root!.Name.Namespace;
        string? obj = null, image = null, handle = null;
        var pid = 0;
        var eventId = int.TryParse(doc.Descendants(ns + "EventID").FirstOrDefault()?.Value, out var parsedId)
            ? parsedId : 0;
        uint accessMask = 0;
        foreach (var d in doc.Descendants(ns + "Data"))
        {
            switch ((string?)d.Attribute("Name"))
            {
                case "ObjectName":  obj = d.Value; break;
                case "ProcessName": image = d.Value; break;
                case "ProcessId":   pid = ParsePid(d.Value); break;
                case "HandleId":    handle = d.Value.Trim(); break;
                case "AccessMask":  accessMask = ParseMask(d.Value); break;
            }
        }
        return new DecoyAuditAccessEvent(eventId, obj, pid, image, handle, accessMask);
    }

    private static uint ParseMask(string value)
    {
        value = value.Trim();
        return value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? uint.TryParse(value[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) ? hex : 0
            : uint.TryParse(value, out var number) ? number : 0;
    }

    private static int ParsePid(string v)
    {
        v = v.Trim();
        try
        {
            return v.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? (int)Convert.ToInt64(v[2..], 16)
                : (int.TryParse(v, out var p) ? p : 0);
        }
        catch { return 0; }
    }

    // Ensures our exact Everyone/ReadData/Success audit ACE is present on a decoy path. Returns true when that
    // ACE is present as a result — whether we just added it, OR an identical one already existed. We ADOPT the
    // pre-existing case because that ACE is our own signature on a decoy WE plant and audit: it can only be a
    // leftover from a prior run that crashed before Cleanup. Adopting it means (a) we count the path as audited
    // so the watcher actually starts, and (b) a clean teardown reclaims and removes it (RemoveAuditRuleSpecific
    // targets ONLY the exact ReadData/Success ACE, so a BROADER pre-existing rule like Everyone/FullControl is
    // still never stripped). Returns false only when the file is missing or the SACL write failed — i.e. the
    // path is NOT being audited and must not keep the watcher alive on its own.
    private static bool EnsureAuditAce(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl(AccessControlSections.Audit);
            var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            const FileSystemRights auditedRights =
                FileSystemRights.ReadData | FileSystemRights.WriteData | FileSystemRights.Delete;
            foreach (FileSystemAuditRule r in sec.GetAuditRules(true, true, typeof(SecurityIdentifier)))
                if (Equals(r.IdentityReference, everyone)
                    && r.FileSystemRights == auditedRights
                    && r.AuditFlags == AuditFlags.Success)
                    return true;   // our exact ACE already present (crash-orphaned) — adopt: watch it, remove on teardown

            sec.AddAuditRule(new FileSystemAuditRule(everyone, auditedRights, AuditFlags.Success));
            fi.SetAccessControl(sec);
            return true;
        }
        catch { return false; }
    }

    // Removes ONLY the exact Everyone/ReadData/Success ACE we added (RemoveAuditRuleSpecific, not ...All —
    // ...All would also strip a broader pre-existing rule like Everyone/FullControl/Success). Called only for
    // paths in _sacled, i.e. where TrySetAuditAce actually added the rule.
    private static void TryRemoveAuditAce(string path)
    {
        try
        {
            if (!File.Exists(path)) return;
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl(AccessControlSections.Audit);
            sec.RemoveAuditRuleSpecific(new FileSystemAuditRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.ReadData | FileSystemRights.WriteData | FileSystemRights.Delete,
                AuditFlags.Success));
            fi.SetAccessControl(sec);
        }
        catch { }
    }

    private void AcquireAuditPolicyOwnership()
    {
        var inheritedLease = TryReadAuditPolMarker(out var priorLease) && priorLease is not null;
        var enabledNow = EnableFileSystemAuditingIfNeeded();

        if (enabledNow)
        {
            // Durability is part of the state transition. If the ownership marker cannot be committed, immediately
            // roll back the policy rather than leaving an unowned machine-wide change after the next crash.
            if (!TryWriteAuditPolMarker())
            {
                DeleteAuditPolMarkerIfOwned();
                TryDisableFileSystemAuditing();
                throw new IOException("Could not persist TraceBrake's audit-policy ownership lease.");
            }
            _weEnabledAuditPol = true;
            return;
        }

        // The policy was already enabled. Reclaim it only from a fresh, ACL-authenticated TraceBrake lease. An absent,
        // malformed, or stale marker means another tool or administrator may own the policy, so leave it untouched.
        _weEnabledAuditPol = inheritedLease && TryWriteAuditPolMarker();
    }

    private void RefreshAuditPolicyLeaseIfDue()
    {
        if (!_weEnabledAuditPol || DateTimeOffset.UtcNow - _lastMarkerRefresh < MarkerRefreshInterval) return;
        TryWriteAuditPolMarker(); // keep retrying on later Drain calls if this transiently fails
    }

    // Returns true only if WE flipped it on (so we revert exactly what we changed).
    private static bool EnableFileSystemAuditingIfNeeded()
    {
        if (RunAuditpol("/get /subcategory:\"File System\"").Contains("Success", StringComparison.OrdinalIgnoreCase))
            return false;
        RunAuditpol("/set /subcategory:\"File System\" /success:enable");
        return true;
    }

    private static void TryDisableFileSystemAuditing()
    {
        try { RunAuditpol("/set /subcategory:\"File System\" /success:disable"); } catch { }
    }

    private static string RunAuditpol(string args)
    {
        var psi = new ProcessStartInfo("auditpol", args)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("auditpol did not start.");
        var outputTask = p.StandardOutput.ReadToEndAsync();
        var errorTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(5000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("auditpol timed out.");
        }
        Task.WaitAll([outputTask, errorTask], 1000);
        var o = outputTask.GetAwaiter().GetResult();
        var error = errorTask.GetAwaiter().GetResult();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"auditpol failed ({p.ExitCode}): {error.Trim()}");
        return o;
    }

    private void Cleanup()
    {
        try { if (_watcher is not null) { _watcher.Enabled = false; _watcher.Dispose(); _watcher = null; } } catch { }
        foreach (var p in _sacled) TryRemoveAuditAce(p);
        _sacled.Clear();
        if (_weEnabledAuditPol)
        {
            // Disable only while the durable lease still names this instance. If ownership was replaced, deleted,
            // or corrupted, another elevated actor may now depend on the policy; fail open rather than claim it.
            if (AuditPolMarkerOwnedByThisInstance())
            {
                TryDisableFileSystemAuditing();
                DeleteAuditPolMarkerIfOwned();
            }
            _weEnabledAuditPol = false;
        }
    }

    // A machine-wide marker recording that WE enabled the "File System" success subcategory, so ownership
    // survives a crash/kill that skips Cleanup: the next elevated run reads it, reclaims ownership, and reverts
    // the policy on clean teardown instead of leaving it orphaned-on. Kept in ProgramData (not per-user
    // LocalAppData) so it is stable no matter which admin account approved the UAC elevation.
    private static string AuditPolMarkerDirectory() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Foreman", "ElevatedState");

    private static string AuditPolMarkerPath() => Path.Combine(AuditPolMarkerDirectory(), "decoy-auditpol.owned");

    private bool TryReadAuditPolMarker(out DecoyAuditOwnershipLease? lease)
    {
        lease = null;
        try
        {
            var marker = AuditPolMarkerPath();
            if (!File.Exists(marker) || !MarkerHasTrustedAcl(marker)) return false;
            if (!DecoyAuditOwnershipLeaseCodec.TryParse(File.ReadAllText(marker), out lease)
                || lease is null
                || !DecoyAuditOwnershipLeaseCodec.IsFresh(lease, DateTimeOffset.UtcNow))
            {
                lease = null;
                return false;
            }
            return true;
        }
        catch { lease = null; return false; }
    }

    private bool TryWriteAuditPolMarker()
    {
        string? temp = null;
        try
        {
            var directory = AuditPolMarkerDirectory();
            HardenMarkerDirectory(directory);
            var marker = AuditPolMarkerPath();
            temp = Path.Combine(directory, $"decoy-auditpol.{Guid.NewGuid():N}.tmp");
            var payload = Encoding.UTF8.GetBytes(
                DecoyAuditOwnershipLeaseCodec.Create(_auditPolInstanceId, DateTimeOffset.UtcNow));
            using (var stream = new FileStream(
                       temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(payload);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, marker, overwrite: true);
            temp = null;
            HardenMarkerFile(marker);

            if (!MarkerHasTrustedAcl(marker)
                || !DecoyAuditOwnershipLeaseCodec.TryParse(File.ReadAllText(marker), out var saved)
                || saved?.InstanceId != _auditPolInstanceId)
                return false;

            _lastMarkerRefresh = DateTimeOffset.UtcNow;
            return true;
        }
        catch { return false; }
        finally { if (temp is not null) TryDeleteMarker(temp); }
    }

    private bool AuditPolMarkerOwnedByThisInstance()
    {
        try
        {
            var marker = AuditPolMarkerPath();
            return File.Exists(marker)
                && MarkerHasTrustedAcl(marker)
                && DecoyAuditOwnershipLeaseCodec.TryParse(File.ReadAllText(marker), out var lease)
                && lease?.InstanceId == _auditPolInstanceId;
        }
        catch { return false; }
    }

    private void DeleteAuditPolMarkerIfOwned()
    {
        if (AuditPolMarkerOwnedByThisInstance()) TryDeleteMarker(AuditPolMarkerPath());
    }

    private static void HardenMarkerDirectory(string path)
    {
        var directory = Directory.CreateDirectory(path);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(admins);
        const InheritanceFlags inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            admins, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl, inheritance, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(security);
    }

    private static void HardenMarkerFile(string path)
    {
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(admins);
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    private static bool MarkerHasTrustedAcl(string path)
    {
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier));
        if (!Equals(owner, admins) && !Equals(owner, system)) return false;

        const FileSystemRights writeRights = FileSystemRights.WriteData | FileSystemRights.AppendData
            | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes | FileSystemRights.Delete
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || (rule.FileSystemRights & writeRights) == 0) continue;
            if (!Equals(rule.IdentityReference, admins) && !Equals(rule.IdentityReference, system)) return false;
        }
        return true;
    }

    private static void TryDeleteMarker(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    public void Dispose() => Cleanup();

    // ── enable SeSecurityPrivilege in this (elevated) token, required to write a SACL ──────────────────
    [StructLayout(LayoutKind.Sequential)] private struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] private struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool LookupPrivilegeValue(string? system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState, uint len, IntPtr prev, IntPtr retLen);

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8, SE_PRIVILEGE_ENABLED = 0x2;

    private static void EnablePrivilege(string name)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var tok)) return;
        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid)) return;
            var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = SE_PRIVILEGE_ENABLED };
            AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally { CloseHandle(tok); }
    }
}
