# TraceBrake Release Checklist

Use this before publishing a public binary release.

Run the Release workflow manually with **Publish a GitHub Release** left off first. This builds the complete
installer on the release runner and uploads a seven-day Actions candidate without creating a tag or Release.
Only publish from `main` after that candidate passes the checks below.

## Required

- Run `powershell -NoProfile -File .\scripts\Invoke-DotNetTests.ps1 -Configuration Release` and retain the TRX evidence path it prints.
  The script runs on Windows PowerShell 5.1 and on PowerShell 7 (`pwsh`); CI uses `pwsh`.
- Run `dotnet build .\src\Foreman.App\Foreman.App.csproj -c Release`.
- Run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Test-ReleasePayload.ps1` against the
  release-equivalent `publish` directory and confirm all five payload executables carry the intended release version.
- Run `scripts\Test-ReleasePayloadBypasses.ps1` against that payload and confirm hidden helper siblings and
  packaged extension test fixtures are both rejected before the clean payload is revalidated.
- Verify a clean install on a fresh Windows 10/11 x64 VM.
- Verify uninstall removes app files and run-at-login registration.
- Verify first run opens the Connect Agent path and supports Claude Code and Codex.
- Verify both unpacked MV3 extensions are installed under `<install>\extensions`, contain no test fixtures,
  and can be loaded and paired from Chrome without cloning the repository.
- Verify `/health` is reachable and `/mcp` rejects missing or wrong bearer tokens.
- Verify a connected Claude Code or Codex session appears in the dashboard.
- Verify Ask Harness delivery for at least one connected client.
- Verify MCP inventory treats TraceBrake's own `foreman` loopback server as informational.
- Capture fresh screenshots for README/release notes.
- Attach SHA-256 checksums to the release.
- State clearly whether the installer is signed or unsigned (see **Code Signing** below).
- Confirm the generated release disclosure identifies `v0.1.0-alpha3` as the immutable Build Week snapshot and
  labels every later build as post-submission maintenance/development.
- Confirm the "Attest build provenance" step succeeded (see **Build Provenance** below); it runs on every
  release with no setup, so a failure there means the release lacks a verifiable provenance record.

## Recommended

- Test installer upgrade over a previous version.
- Confirm a running Foreman instance blocks install/upgrade through `AppMutex` rather than mixing file versions.
- Test run-at-login on/off.
- Test `RunElevated` sidecar opt-in and opt-out.
- Test `ScanMcpTools` with a harmless HTTP MCP server.
- Confirm all screenshots avoid exposing user paths, tokens, project names, or private terminal output.
- Confirm release notes state the supported stable .NET 10 SDK/runtime and Windows versions accurately.
- Review SECURITY.md and README.md for claims that drifted since the last release.
- Review and intentionally update the pinned `INNO_SETUP_VERSION`; never silently consume the runner's latest
  compiler.

## Code Signing (SignPath Foundation)

Foreman signs via **SignPath Foundation** — free Authenticode (OV) signing for OSS, done in SignPath's
cloud HSM. The release workflow's signing steps are **opt-in**: they run only when the repo variable
`SIGNPATH_ORGANIZATION_ID` is set. Until then, releases build and ship **unsigned** (checksums only) and
nothing in CI breaks. Why OV-via-SignPath and not EV/a purchased cert: see
[docs/audit-2026-06-10.md] notes and the README — in 2026 EV no longer shortcuts SmartScreen, and OV is
the only $0 path that produces a real signature whose reputation transfers across releases.

### One-time setup

1. **Apply to SignPath Foundation** at <https://signpath.io/open-source> (GPL-3.0 qualifies). Link the
   GitHub repo and enable MFA on both SignPath and GitHub. *Note:* SignPath's terms exclude malware/PUP,
   and Foreman's process-monitoring / ETW / config-writing behaviour is exactly what gets tools
   *misclassified*. Be ready to explain the project; if they decline, the fallback is Azure Artifact
   Signing (~$10/mo, US/Canada individuals) — same workflow shape, different action.
2. In SignPath, create the **project** and a **signing policy** (e.g. `release-signing`). **Enable
   timestamping in the policy** — signatures must outlive the (short-lived) cert.
3. Create **two artifact configurations**:
   - **App** (`SIGNPATH_APP_ARTIFACT_CONFIG_SLUG`): input is the uploaded `publish` folder (a zip). Sign
     `TraceBrake.exe`, `sidecar/Foreman.EtwSidecar.exe`, `guardian/Foreman.Guardian.exe`,
     `cu-sidecar/Foreman.CuSidecar.exe`, and `cu-pilot/Foreman.CuPilot.exe`; pass everything else through.
     Every inner PE must be signed before the installer is built around it. The workflow verifies this and fails
     before packaging if the external SignPath configuration omitted one.
   - **Installer** (`SIGNPATH_INSTALLER_ARTIFACT_CONFIG_SLUG`): input is the single
     `TraceBrake-Setup-*.exe`; sign it.
4. Generate a SignPath **API token**.

### GitHub configuration

Settings → Secrets and variables → Actions:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `SIGNPATH_API_TOKEN` | the SignPath API token |
| Variable | `SIGNPATH_ORGANIZATION_ID` | SignPath organization id (**this var is the on/off switch**) |
| Variable | `SIGNPATH_PROJECT_SLUG` | SignPath project slug |
| Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | e.g. `release-signing` |
| Variable | `SIGNPATH_APP_ARTIFACT_CONFIG_SLUG` | the App artifact-configuration slug |
| Variable | `SIGNPATH_INSTALLER_ARTIFACT_CONFIG_SLUG` | the Installer artifact-configuration slug |

### How the workflow signs (nested order)

`publish` → **sign all five app-payload executables** → build Inno installer from the signed payload →
**sign installer** → checksums (over the signed installer) → attach to release. Signing only the installer
would leave the inner exes untrusted at runtime, so the order matters. The workflow uses
`signpath/github-action-submit-signing-request@v2`: it `actions/upload-artifact`s each stage, submits the
artifact id to SignPath, and writes the signed result back via `output-artifact-directory`.

### Reality check (set release-note expectations)

Even once signed, early releases still show SmartScreen "unrecognized app" until the cert/file-hash earns
reputation (Microsoft: weeks + hundreds of clean installs). For a niche tool that may never fully accrue —
keep the SHA-256 checksums, walk users through "More info → Run anyway" in the install docs, and **sign
every release with the same identity** so reputation compounds. Do **not** buy EV (no SmartScreen benefit
in 2026; only needed for kernel drivers, which Foreman doesn't ship).

## Build Provenance (GitHub Artifact Attestations)

Separate from, and complementary to, Authenticode signing. The release workflow's "Attest build provenance"
step produces a keyless (Sigstore, OIDC-backed) attestation that binds each shipped artifact to the exact
repo, commit, and workflow run that built it. It answers "did this binary really come from this source?",
which code signing (which answers "who published this?") does not.

- **No setup.** It has no secrets or variables to configure and runs on every release, signed or unsigned. It
  runs after the SignPath steps, so when signing is on it attests the final signed bytes.
- **What is attested:** the installer plus all five payload binaries (`TraceBrake.exe`, ETW sidecar, Guardian,
  desktop-CU sidecar, and Local Agent Host pilot), so a user can verify either the download or an installed file.
- **Nothing is attached to the Release.** GitHub stores the attestation; verification fetches it by digest.
- **Verify a download or an installed file:**

  ```
  gh attestation verify <path-to-exe> --repo aXL333/Foreman
  ```

  A pass prints the source repo, commit, and workflow. Worth putting this one line in the release notes so
  security-minded users can check what they ran.
- **Relation to the sidecar integrity gate:** provenance is a build-time supply-chain proof. It does not
  replace the runtime Authenticode signer-match check in `SidecarIntegrity` (which needs the SignPath cert to
  become active); the two are independent and both worth having.

## Current Alpha Gates

- Real app screenshots are still needed before broader announcement.
- OpenCode and T3 Code profiles are included but need field verification.
- LLM triage preferences are configurable in JSON; a full UI editor is still roadmap.
