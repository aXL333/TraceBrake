# Code Signing

This document describes how TraceBrake release binaries are (or will be) code-signed, and how
you can verify a download. It exists both for transparency to users and as a reference for the
[SignPath Foundation](https://signpath.org/) open-source signing program.

## Current status

TraceBrake is in **alpha**. Until code signing is approved and live, release artifacts are
shipped **unsigned**, accompanied by **SHA-256 checksums** (`checksums-sha256.txt`) so you can verify
integrity. Release notes state clearly whether a given build is signed.

## Signing approach

Foreman uses **free Authenticode (OV) code signing provided by [SignPath Foundation](https://signpath.org/)**
for qualifying open-source projects. Key properties of this model:

- The signing certificate is **issued to and held by SignPath Foundation**, whose HSM stores the private
  key — the maintainer never possesses the key. The **publisher shown to users is "SignPath Foundation."**
- Signing happens **only in CI**, on tagged releases, from sources built in this repository — see
  [`.github/workflows/release.yml`](.github/workflows/release.yml) and
  [`docs/release-checklist.md`](docs/release-checklist.md).
- The signing pipeline is **opt-in and gated** on a repository variable, so the project builds and releases
  cleanly whether or not signing is configured.

### What gets signed, and in what order

Signing is nested so the installer ships already-signed binaries:

1. Every executable in the app payload is signed first: **`TraceBrake.exe`**,
   **`sidecar/Foreman.EtwSidecar.exe`**, **`guardian/Foreman.Guardian.exe`**,
   **`cu-sidecar/Foreman.CuSidecar.exe`**, and **`cu-pilot/Foreman.CuPilot.exe`**.
2. The **Inno Setup installer** (`TraceBrake-Setup-*.exe`) is built from those signed binaries and
   then signed last.
3. SHA-256 checksums are generated over the final, signed installer.

All signatures are **timestamped**, so they remain valid after the (short-lived) certificate expires.

The optional Guardian uses the same verified Authenticode identity as its long-lived client policy. A signed
installation pins the publisher, so later releases signed by that publisher continue to work without a binary hash
re-pin. Unsigned development installations instead pin the exact TraceBrake.exe path and SHA-256 and are explicitly
reported as development-only protection; re-enabling the Guardian after signing upgrades that policy.

## Attribution

As required by the SignPath Foundation program, once releases are signed they credit:

> Free code signing provided by [SignPath.io](https://signpath.io/), certificate by
> [SignPath Foundation](https://signpath.org/).

This attribution appears in the release notes and the application's About information.

## Verifying a download

**Checksum (always available):**

```powershell
Get-FileHash .\TraceBrake-Setup-<version>.exe -Algorithm SHA256
# compare against checksums-sha256.txt attached to the release
```

**Authenticode signature (once signed):** right-click the installer → *Properties* → *Digital Signatures*,
or:

```powershell
Get-AuthenticodeSignature .\TraceBrake-Setup-<version>.exe | Format-List
# Expect: Status = Valid, signed by "SignPath Foundation"
```

Note that a freshly published signed build may still trigger a Microsoft SmartScreen "unrecognized app"
prompt until its reputation accrues — this is expected for a low-volume tool and does not indicate a problem
with the signature. The checksum and the "SignPath Foundation" publisher are the authoritative checks.
