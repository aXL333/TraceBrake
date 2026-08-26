# OpenAI Build Week 2026

> **Historical name:** the submission and immutable evidence below use the project's competition-era name,
> **Foreman Agent Safety**. The maintained product was renamed **TraceBrake** after the competition; no
> submission-period record, tag, demo or eligibility claim has been rewritten.

Foreman Agent Safety is a pre-existing open-source project. This document separates its earlier development
from the extension produced during the OpenAI Build Week 2026 submission period.

## Baseline and eligible extension

- **Pre-event baseline:** `76aede6` (`feat(liveweave): add visual page editing workflow`), committed
  2026-07-13 at 18:33:42 ACST, before the submission period opened.
- **Initial Build Week integration commit:** `06c0fdc` (`fix: harden security boundaries and release validation`),
  committed 2026-07-20 at 00:28:02 ACST.
- **Immutable submission release:** `v0.1.0-alpha3` at `c5fd504`, which carries the later Build Week Android/ADB
  bridge work. The release tag identifies the exact deadline build and will not be moved or replaced.
- **Recorded change set:** 49 files changed, with 1,765 additions and 228 removals.

The integration commit is a code boundary, not a complete transcript of the work. Timestamped Codex sessions
record the corresponding investigation, threat modelling, implementation, review, and testing. The Devpost
submission provides the required `/feedback` Codex session ID. Earlier Codex sessions explain Foreman's
development history, but only work completed after the submission period opened is presented for Build Week
judging.

## Post-submission maintenance boundary

The submission period closed on 21 July 2026 at 5:00 PM PT. Commits after `c5fd504` are not claimed as
Build Week work. The repository and maintained installers may receive clearly identified security, reliability,
packaging, and ordinary development updates during judging because the rules require the working project to
remain available for testing. Those updates do not change the Devpost submission, demo, `/feedback` session ID,
or the immutable `v0.1.0-alpha3` evidence tag.

For eligibility review, use `v0.1.0-alpha3`. For hands-on installation, use the newest maintained pre-release
and read its release disclosure; later builds may contain post-deadline security corrections that deliberately
fail closed where the submission snapshot did not.

## How Codex contributed

Codex has been part of Foreman's development since the project began. It has helped investigate Windows
security boundaries, plan features, challenge architectural assumptions, review implementations, generate
tests, diagnose failures, improve documentation, and conduct repeated functional and adversarial audits.

During Build Week, Codex with GPT-5.6 was used as both an engineering collaborator and an adversarial reviewer.
The working loop was:

1. Define the component's intended security boundary.
2. Model a compromised, confused, or overconfident harness.
3. Develop a concrete failure or attack scenario.
4. Implement a narrowly scoped correction.
5. Add regression coverage.
6. Verify that ordinary multi-harness development still worked.

The human maintainer retained responsibility for product direction, authority boundaries, accepted risk,
operator-presence requirements, and the final decision to integrate or reject each proposed change.

## Build Week work

The eligible extension includes:

- Guardian caller authentication for signed releases and explicitly labelled unsigned development builds.
- Exact executable path plus SHA-256 pinning for unsigned Guardian clients, with an upgrade path to verified
  publisher trust when signing becomes available.
- Release-payload layout, version, signing-mode, and provenance validation.
- Event-log integrity and temporal-ordering improvements.
- Scheduled independent-audit tracking and regression coverage.
- Safer agent-configuration and repository scanning.
- MCP session, SSE, and broker-boundary hardening.
- Crash-handling and diagnostic improvements.
- LiveWeave input-boundary and project-model hardening.
- A bounded Android/ADB bridge inside the shared `cu_*` computer-use broker: explicit device enrolment, an
  operator-selected and SHA-256-pinned `adb.exe`, observe-only inventory/screenshot/UI-tree/log actions,
  approval-held APK install/tap/type/swipe/key actions, bounded output and timeouts, per-harness driver policy, and
  panic-stop cancellation. APK approval is bound to Foreman's canonical path, byte count and SHA-256, then re-pinned
  and re-verified at execution so a same-path package swap cannot ride an earlier approval. No raw `adb shell`
  surface is exposed to harnesses.
- New transport, security, scanner, event-log, scheduled-audit, and release-validation tests.

## Installation and judge testing

Foreman supports Windows 10/11 x64.

1. For hands-on testing, download the newest maintained pre-release installer and `checksums-sha256.txt` from
   [GitHub Releases](https://github.com/aXL333/TraceBrake/releases).
2. For deadline/eligibility review, use the immutable `v0.1.0-alpha3` tag at `c5fd504`. Do not treat
   post-deadline maintenance commits as submission-period work.
3. Verify the installer checksum, then install and launch Foreman from the Windows tray.
4. Use **Connect agent** to configure Codex, Claude Code, or Cursor; Foreman backs up the existing harness
   configuration before changing its own MCP entry.
5. Confirm the harness appears on the dashboard and can call `foreman_status`.
6. Use `Foreman.TestHarness` or a connected coding agent to exercise the Ask Harness response loop.
7. Review process attribution, behaviour escalation, the event log, MCP inventory, and the repository
   agent-configuration scanner.
8. To test the optional Android path, enable Presence Lock, select and enrol the Android SDK
   `platform-tools\\adb.exe` under **Settings -> Computer use**, enrol a connected device serial, then enable the
   bridge and restart Foreman. An approved harness can call `cu_submit` with `modality="android"` for `devices`,
   `screenshot`, `ui_dump`, or capped `logcat`; input actions remain held for operator approval.

The optional Hardened Guardian and elevated ETW network sidecar require explicit operator enablement. They are
not required for the normal monitoring and Ask Harness demonstration. The Android/ADB bridge is also disabled by
default and does not grant a harness raw shell access or permission to target an unenrolled device.

Alpha installers may be unsigned until the documented SignPath configuration is available. Each release
therefore states its signing mode automatically and includes SHA-256 checksums and GitHub build-provenance
attestations. Unsigned Release builds fail closed for the optional LocalSystem Guardian.
