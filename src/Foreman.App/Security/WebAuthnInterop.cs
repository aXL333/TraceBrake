using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Foreman.App.Security;

/// <summary>
/// Minimal P/Invoke over <c>webauthn.dll</c> (Windows WebAuthn platform API) for a LOCAL presence check —
/// enroll one credential, then assert it. The native picker aggregates the platform authenticator (Windows
/// Hello) AND roaming FIDO2/U2F keys (YubiKey), so one path covers "all authenticators". The user-verification
/// requirement is caller-chosen: DISCOURAGED (touch-only, the default — a roaming key needs just a touch, no PIN)
/// or PREFERRED (PIN/biometric when the key supports it). Either way attestation is NONE (we are not a
/// relying-party server — HRESULT S_OK from a fresh ceremony IS the proof a present human authorized it; there is
/// no replay surface for a same-machine process because the OS runs the ceremony itself), and a fresh ceremony
/// always requires at least a physical touch, which is the one thing a same-user process cannot fake.
///
/// Definitions verified against the canonical Microsoft <c>webauthn.h</c>. Marshalling is manual (explicit
/// IntPtrs, deterministic alloc/free) — no ambiguity about who frees what. Struct layouts are
/// <see cref="LayoutKind.Sequential"/> with default (natural) packing, which matches the native header.
/// The calls are SYNCHRONOUS/BLOCKING — callers must invoke off the UI thread (see WebAuthnPresenceVerifier).
/// </summary>
internal static class WebAuthnInterop
{
    // DISCOURAGED (default) = touch-only: a roaming key is insert + a single touch, no forced FIDO2 PIN. That
    // alone fully stops the rogue-agent threat (software can't touch a physical key). PREFERRED (opt-in) adds
    // full PIN/biometric where the key supports it — physical-key-theft hardening. The caller picks per-ceremony;
    // see PresenceLockSettings.RequireUserVerification. (Hello/platform always verifies fully regardless.)
    private const int WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED = 2;
    private const int WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 3;
    private const int WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;          // platform (Hello) + cross-platform (keys)
    private const int WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 1;
    private const int COSE_ES256 = -7;
    private const int COSE_RS256 = -257;
    private const string PUBLIC_KEY = "public-key";
    private const string SHA_256 = "SHA-256";
    private const int TIMEOUT_MS = 120_000;                              // generous; the gate has its own UX
    private const int S_OK = 0;

    // ── structs (verbatim field order from webauthn.h; pointers as IntPtr, BOOL as int) ──────────────────
    [StructLayout(LayoutKind.Sequential)]
    private struct RpInfo { public int dwVersion; public IntPtr pwszId; public IntPtr pwszName; public IntPtr pwszIcon; }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserInfo
    {
        public int dwVersion; public int cbId; public IntPtr pbId;
        public IntPtr pwszName; public IntPtr pwszIcon; public IntPtr pwszDisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ClientData { public int dwVersion; public int cbClientDataJSON; public IntPtr pbClientDataJSON; public IntPtr pwszHashAlgId; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CoseParam { public int dwVersion; public IntPtr pwszCredentialType; public int lAlg; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CoseParams { public int cCredentialParameters; public IntPtr pCredentialParameters; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Credential { public int dwVersion; public int cbId; public IntPtr pbId; public IntPtr pwszCredentialType; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Credentials { public int cCredentials; public IntPtr pCredentials; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Extensions { public int cExtensions; public IntPtr pExtensions; }

    // MAKE_CREDENTIAL_OPTIONS, version 1 (dwVersion=1 → the API reads only these fields).
    [StructLayout(LayoutKind.Sequential)]
    private struct MakeOptions
    {
        public int dwVersion; public int dwTimeoutMilliseconds;
        public Credentials CredentialList; public Extensions Extensions;
        public int dwAuthenticatorAttachment; public int bRequireResidentKey;
        public int dwUserVerificationRequirement; public int dwAttestationConveyancePreference; public int dwFlags;
    }

    // GET_ASSERTION_OPTIONS, version 1 (the legacy embedded CredentialList is the allow-list; works on all versions).
    [StructLayout(LayoutKind.Sequential)]
    private struct GetOptions
    {
        public int dwVersion; public int dwTimeoutMilliseconds;
        public Credentials CredentialList; public Extensions Extensions;
        public int dwAuthenticatorAttachment; public int dwUserVerificationRequirement; public int dwFlags;
    }

    // CREDENTIAL_ATTESTATION prefix — only up to pbCredentialId (PtrToStructure reads just this many bytes).
    [StructLayout(LayoutKind.Sequential)]
    private struct AttestationHeader
    {
        public int dwVersion; public IntPtr pwszFormatType;
        public int cbAuthenticatorData; public IntPtr pbAuthenticatorData;
        public int cbAttestation; public IntPtr pbAttestation;
        public int dwAttestationDecodeType; public IntPtr pvAttestationDecode;
        public int cbAttestationObject; public IntPtr pbAttestationObject;
        public int cbCredentialId; public IntPtr pbCredentialId;
    }

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern int WebAuthNGetApiVersionNumber();

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern int WebAuthNAuthenticatorMakeCredential(
        IntPtr hWnd, ref RpInfo rp, ref UserInfo user, ref CoseParams pubKeyCredParams,
        ref ClientData clientData, ref MakeOptions options, out IntPtr ppAttestation);

    [DllImport("webauthn.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WebAuthNAuthenticatorGetAssertion(
        IntPtr hWnd, string pwszRpId, ref ClientData clientData, ref GetOptions options, out IntPtr ppAssertion);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern void WebAuthNFreeCredentialAttestation(IntPtr p);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern void WebAuthNFreeAssertion(IntPtr p);

    [DllImport("webauthn.dll", ExactSpelling = true)]
    private static extern IntPtr WebAuthNGetErrorName(int hr);

    /// <summary>WebAuthn API version, or 0 if webauthn.dll is absent (pre-Win10-1903). Used for availability.</summary>
    public static int ApiVersion()
    {
        try { return WebAuthNGetApiVersionNumber(); } catch { return 0; }
    }

    /// <summary>Enroll a credential (the user taps Hello or a key). Returns the credential id bytes, or null + an error.</summary>
    public static (bool Ok, byte[]? CredentialId, string? Error) MakeCredential(IntPtr hWnd, string rpId, string rpName, bool requireUserVerification)
    {
        var keep = new List<IntPtr>();
        var ppAtt = IntPtr.Zero;
        try
        {
            var pType = Str(keep, PUBLIC_KEY);
            var rp = new RpInfo { dwVersion = 1, pwszId = Str(keep, rpId), pwszName = Str(keep, rpName) };
            var uid = RandomNumberGenerator.GetBytes(16);
            var pUserName = Str(keep, "TraceBrake operator");
            var user = new UserInfo { dwVersion = 1, cbId = uid.Length, pbId = Bytes(keep, uid), pwszName = pUserName, pwszDisplayName = pUserName };

            var cose = new[]
            {
                new CoseParam { dwVersion = 1, pwszCredentialType = pType, lAlg = COSE_ES256 },
                new CoseParam { dwVersion = 1, pwszCredentialType = pType, lAlg = COSE_RS256 },
            };
            var coseList = new CoseParams { cCredentialParameters = cose.Length, pCredentialParameters = StructArray(keep, cose) };

            var cd = RandomNumberGenerator.GetBytes(32);
            var clientData = new ClientData { dwVersion = 1, cbClientDataJSON = cd.Length, pbClientDataJSON = Bytes(keep, cd), pwszHashAlgId = Str(keep, SHA_256) };

            var options = new MakeOptions
            {
                dwVersion = 1, dwTimeoutMilliseconds = TIMEOUT_MS,
                dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                bRequireResidentKey = 0,                                            // non-discoverable: we keep the id
                dwUserVerificationRequirement = requireUserVerification
                    ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED
                    : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
                dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            };

            var hr = WebAuthNAuthenticatorMakeCredential(hWnd, ref rp, ref user, ref coseList, ref clientData, ref options, out ppAtt);
            if (hr != S_OK) return (false, null, ErrorName(hr));
            if (ppAtt == IntPtr.Zero) return (false, null, "No attestation returned.");

            var att = Marshal.PtrToStructure<AttestationHeader>(ppAtt);
            if (att.cbCredentialId <= 0 || att.pbCredentialId == IntPtr.Zero) return (false, null, "No credential id returned.");
            var id = new byte[att.cbCredentialId];
            Marshal.Copy(att.pbCredentialId, id, 0, att.cbCredentialId);
            return (true, id, null);
        }
        finally
        {
            if (ppAtt != IntPtr.Zero) WebAuthNFreeCredentialAttestation(ppAtt);
            FreeAll(keep);
        }
    }

    /// <summary>Assert the pinned credential (the user taps). Returns true only on a verified ceremony (S_OK).</summary>
    public static (bool Ok, string? Error) GetAssertion(IntPtr hWnd, string rpId, byte[] credentialId, bool requireUserVerification)
    {
        var keep = new List<IntPtr>();
        var ppAssert = IntPtr.Zero;
        try
        {
            var cred = new Credential { dwVersion = 1, cbId = credentialId.Length, pbId = Bytes(keep, credentialId), pwszCredentialType = Str(keep, PUBLIC_KEY) };
            var credList = new Credentials { cCredentials = 1, pCredentials = StructArray(keep, new[] { cred }) };

            var cd = RandomNumberGenerator.GetBytes(32);
            var clientData = new ClientData { dwVersion = 1, cbClientDataJSON = cd.Length, pbClientDataJSON = Bytes(keep, cd), pwszHashAlgId = Str(keep, SHA_256) };

            var options = new GetOptions
            {
                dwVersion = 1, dwTimeoutMilliseconds = TIMEOUT_MS, CredentialList = credList,
                dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                dwUserVerificationRequirement = requireUserVerification
                    ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED
                    : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
            };

            var hr = WebAuthNAuthenticatorGetAssertion(hWnd, rpId, ref clientData, ref options, out ppAssert);
            return hr == S_OK ? (true, null) : (false, ErrorName(hr));
        }
        finally
        {
            if (ppAssert != IntPtr.Zero) WebAuthNFreeAssertion(ppAssert);
            FreeAll(keep);
        }
    }

    private static string ErrorName(int hr)
    {
        var name = "";
        try { var p = WebAuthNGetErrorName(hr); if (p != IntPtr.Zero) name = Marshal.PtrToStringUni(p) ?? ""; } catch { }
        return string.IsNullOrEmpty(name) ? $"0x{hr:X8}" : $"{name} (0x{hr:X8})";   // always carry the code for diagnosis
    }

    // ── manual unmanaged allocation, all tracked in `keep` and freed in finally ──────────────────────────
    private static IntPtr Str(List<IntPtr> keep, string s) { var p = Marshal.StringToHGlobalUni(s); keep.Add(p); return p; }

    private static IntPtr Bytes(List<IntPtr> keep, byte[] b)
    {
        var p = Marshal.AllocHGlobal(b.Length);
        Marshal.Copy(b, 0, p, b.Length);
        keep.Add(p);
        return p;
    }

    private static IntPtr StructArray<T>(List<IntPtr> keep, T[] arr) where T : struct
    {
        var sz = Marshal.SizeOf<T>();
        var p = Marshal.AllocHGlobal(sz * arr.Length);
        for (var i = 0; i < arr.Length; i++) Marshal.StructureToPtr(arr[i], p + i * sz, false);
        keep.Add(p);
        return p;
    }

    private static void FreeAll(List<IntPtr> keep)
    {
        foreach (var p in keep) if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
    }
}
