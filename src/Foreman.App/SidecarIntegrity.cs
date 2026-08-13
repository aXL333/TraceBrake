using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace Foreman.App;

/// <summary>
/// Gates whether the elevated sidecar binary is trustworthy to launch <b>with administrator rights</b>.
///
/// The sidecar lives in a same-user-writable install dir, so a monitored agent could overwrite it and — because
/// the sidecar manifest forces requireAdministrator — turn TraceBrake's own (publisher-branded) UAC prompt into a
/// privilege-escalation primitive. Defence: the sidecar must carry the SAME valid Authenticode signature as the
/// running TraceBrake.exe. This auto-adapts: in a signed release build an attacker's unsigned/differently-signed
/// sidecar is refused; in an unsigned dev build (no trust anchor exists) it allows, since dev isn't the threat
/// model and the LPE targets the signed, branded release. The signer comparison is a pure, testable decision
/// (<see cref="Decide"/>); the Authenticode extraction is Windows interop (<see cref="Verify"/>).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class SidecarIntegrity
{
    /// <summary>
    /// Pure trust decision from the two binaries' VERIFIED signer thumbprints (null = unsigned/invalid signature).
    /// </summary>
    public static (bool Trusted, string Reason) Decide(string? selfSigner, string? sidecarSigner)
    {
        if (selfSigner is null)
            return (true, "TraceBrake itself is unsigned (dev build) — sidecar signature not enforced.");
        if (sidecarSigner is null)
            return (false, "the sidecar is unsigned or its Authenticode signature is invalid, but TraceBrake is signed.");
        if (!string.Equals(selfSigner, sidecarSigner, StringComparison.OrdinalIgnoreCase))
            return (false, "the sidecar is signed by a different publisher than Foreman.");
        return (true, "sidecar Authenticode signature matches TraceBrake's publisher.");
    }

    /// <summary>Verifies the sidecar against the running TraceBrake.exe. Never throws.</summary>
    public static (bool Trusted, string Reason) Verify(string sidecarPath)
    {
        try
        {
            return Decide(VerifiedSignerThumbprint(Environment.ProcessPath),
                          VerifiedSignerThumbprint(sidecarPath));
        }
        catch
        {
            // If verification itself faults, fail CLOSED only when TraceBrake is signed; otherwise (dev) allow.
            var selfSigned = SafeVerifiedSigner(Environment.ProcessPath) is not null;
            return selfSigned
                ? (false, "sidecar integrity check failed unexpectedly while TraceBrake is signed.")
                : (true, "sidecar integrity check inconclusive; TraceBrake is unsigned (dev).");
        }
    }

    private static string? SafeVerifiedSigner(string? p) { try { return VerifiedSignerThumbprint(p); } catch { return null; } }

    /// <summary>True if the running TraceBrake.exe carries a valid Authenticode signature (a release build). When false
    /// (an unsigned dev build) the signer-match gate is WAIVED, so a caller that grants real authority off the back of
    /// a verified sidecar must apply an additional safeguard (the desktop CU path holds an at-rest write/delete lock on
    /// its sidecar binary for exactly this reason).</summary>
    public static bool SelfIsSigned() => SafeVerifiedSigner(Environment.ProcessPath) is not null;

    /// <summary>Authenticode signer-cert thumbprint IF the file's embedded signature is valid (chains to a trusted root); else null.</summary>
    private static string? VerifiedSignerThumbprint(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        if (!IsAuthenticodeValid(path)) return null;
        try
        {
            // CreateFromSignedFile extracts the Authenticode SIGNER cert from a signed PE — the suggested
            // X509CertificateLoader only loads certificate FILES, so it can't replace this. Validity is already
            // established by IsAuthenticodeValid (WinVerifyTrust) above; here we only read the signer identity.
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.Thumbprint;
        }
        catch { return null; }
    }

    // ── WinVerifyTrust interop ──────────────────────────────────────────────────────────────────────
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2, WTD_SAFER_FLAG = 0x100;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    private static bool IsAuthenticodeValid(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
        };
        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_SAFER_FLAG,
        };
        var pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, fDeleteOld: false);
            data.pFile = pFile;
            Marshal.StructureToPtr(data, pData, fDeleteOld: false);

            var result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            // Always close the verify state, regardless of the result.
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, pData, fDeleteOld: false);
            WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            return result == 0;   // 0 = signed, valid, and trusted
        }
        finally
        {
            Marshal.FreeHGlobal(pData);
            Marshal.FreeHGlobal(pFile);
        }
    }
}
