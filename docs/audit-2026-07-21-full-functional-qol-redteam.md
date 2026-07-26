# Foreman Full Audit — Functional, QOL, and Red-Team (2026-07-21)

**Snapshot:** commit `c5fd504` (merge of "complete bounded Android ADB bridge"). Independent second-opinion pass — Codex/GPT-5.6 already ran its own adversarial review while building the Build Week extension (see `docs/openai-build-week-2026.md`); this audit does not assume that review caught everything and does not defer to it.

## 1. Executive Summary

Foreman's foundational security engineering is genuinely strong: the MCP auth gate, the Vault's cryptography, the Guardian's per-connection caller verification, the decoy read-audit design, and the Desktop computer-use path (panic-stop checked before every single input, an independent hard floor, presence-gated approval that survives a stolen operator token) are all well-reasoned and mostly correctly implemented. But four **CRITICAL** gaps survive this pass, and three of them share a common root: **Foreman detects tampering in several places but does not consistently *act* on that detection** — a settings.json edit is flagged but never reverted, a Guardian install-time trust decision can be pointed at attacker-chosen input, and a flood of fabricated alerts can push a genuine Critical event off the operator's visible feed with no severity-aware protection. The fourth (only the sidecar's entry-point `.exe` is integrity-checked, not the DLLs it loads) undermines a defense the code believes is airtight.

The newest code — the Android/ADB bridge — is the least mature relative to its own stated guarantees. Its core claim (no raw shell, allowlisted argument construction) holds up well under direct attack. But the scaffolding around it is incomplete: Settings changes never reach the running bridge (a revoked device stays live until restart — found independently three separate ways), Held Android actions can be approved with no presence tap (unlike Desktop), panic-stop can lose a narrow race, and the SHA-256 binary pin has a real, reproducible TOCTOU via NTFS junctions.

None of this should block continuing to build — it should reprioritize the next work session. Section 8 gives a concrete order.

## 2. Scope & Methodology

**Coverage:** 11 subsystems, each deep-read by a dedicated agent: app composition/UI, core detection & repo scanning, decoys & presence, event-log integrity & setup health, MCP server surface, elevated ETW sidecar, Guardian watchdog, Vault, desktop computer-use, the new Android/ADB bridge, and monitor/platform/release pipeline. Five adversarial personas then hunted for chains crossing subsystem boundaries: a malicious MCP-authenticated harness, a same-user attacker never touching MCP, a build/release-pipeline attacker, a human-factors/alert-fatigue auditor, and a dedicated Android-bridge adversary.

**What wasn't covered / was thin:** LiveWeave (extension-liveweave/) was excluded — it was Codex's actively-changing uncommitted work when this audit was scoped, then landed mid-run; it already has its own dedicated 37-finding review (2026-07-08). CuSidecar/CuPilot's own internals got secondary rather than primary attention (covered mainly through the Desktop CU comparison). Foreman.Platform/Linux was confirmed clean but only lightly read (small surface).

**Prior audits on file:** a functionality audit (2026-06-17, 25 defects, mostly fixed), a security review (2026-06-16, 45 findings — its headline CRITICAL, a `FalsePositiveFilter` process-name-suppression bypass, is confirmed genuinely fixed, see §4.5), and the LiveWeave review (2026-07-08, 37 findings, addressed). This pass focused on what's new since: the Build Week hardening commit, and everything Android.

**Verification:** every finding below carries the confidence the originating agent assigned (`confirmed` = read and traced firsthand; `likely`/`suspected` = strong circumstantial evidence, not fully traced). A second pass ran an adversarial verification panel over the raw pool — 14/15 sampled functional bugs were independently confirmed by a skeptical re-reader, and across ~43 security/attack-chain findings put through a 3-vote refutation panel, 103 of 129 individual votes (80%) did *not* refute the claim. **A script bug in the aggregation step crashed the run before individual verification verdicts could be attributed back to specific findings** — the raw pool below is what a human is reading, not a re-attributed "confirmed by panel" list. To compensate, I personally re-traced the two highest-blast-radius CRITICAL claims against the current code myself before including them (§4.1, §4.2) — both check out exactly as described, code-cited inline.

## 3. Notable Strengths (read this too, not just the problems)

- **MCP auth gate**: every `/mcp` request needs a valid bearer token; peer-PID binding and `CanMutate` fail closed consistently on token theft; per-harness tokens are HMAC-bound so one harness cannot forge another's identity. Applied thoroughly across nearly the entire tool surface, including the new `cu_*` tools.
- **Desktop computer-use path**: panic is checked before *every single SendInput* inside a gesture, backed by an independent hard floor (`CuDesktopPanicFloor`: BlockInput + release-all + TerminateProcess + a watchdog that can't leave the operator locked out), a three-gate sidecar handshake, independent result verification, and presence-gated approval that explicitly survives a stolen operator bearer token (INV-16). This is genuinely well-built and should be the template the Android path is brought up to.
- **Guardian's per-connection caller verification** (not the install-time trust question — see §4.2): every pipe connection is identified via kernel-level `GetNamedPipeClientProcessId` + `QueryFullProcessImageNameW` (unspoofable), and the SHA-256/signer check is recomputed on *every* connection, not just at install — confirmed fail-closed against a rebuilt dev binary by its own tests.
- **Vault cryptography**: AES-256-GCM with header-bound AAD, per-write random salt/nonce, reasonable Argon2id parameters, and a resolver that checks domain-binding before ever touching a secret. The locked-vault deposit queue's forgeability is explicitly and correctly documented as an accepted risk.
- **Android bridge's core argument-construction guarantee holds**: every verb builds a fixed `ArgumentList` template, integers are re-parsed/re-serialized (not blacklisted), `type` text passes a genuine allowlist excluding every shell metacharacter, and device serials are regex-constrained. No raw-shell escape was found anywhere.
- **Release pipeline payload validation genuinely works**: `Test-ReleasePayload.ps1` runs unconditionally before signing and fails the job on a mismatch; GitHub Actions are SHA-pinned throughout (an explicit, correct response to the 2026 actions-hijack incidents per `dependabot.yml`); fork PRs can't reach release secrets.
- **The 2026-06-16 CRITICAL (FalsePositiveFilter bypass) is genuinely fixed** — see §4.5 for the interesting nuance the fix produced.

## 4. Critical Findings

### 4.1 Settings-tamper detection never reverts, and arms everything before it even notifies (root cause, two blast radii) — **CONFIRMED, personally re-traced**

`SettingsStore.Load()` computes a seal verdict but **always returns the settings object regardless** (`src/Foreman.Core/Settings/SettingsStore.cs:67`, verified: `return settings;` with no gate above it). The only reaction anywhere in the codebase is a single High `MonitoringNoticeEvent` fired at `App.xaml.cs:1020-1025` — well after PresenceLock, decoys, the Android bridge, and CU driver authority are already wired up from that same (possibly tampered) settings object earlier in `OnStartup`. There is no revert-to-last-known-sealed-values path anywhere.

Two concrete consequences, found independently by two different passes:
- **Presence-lock bypass**: flip `PresenceLock.Enabled` to `false` in the plain-text, same-user-writable settings.json and every `PresenceGate.AuthorizeAsync` call silently no-ops for the whole session (`PresenceGate.cs:57-58`).
- **Android/ADB bridge hijack** (red-team, `local-non-admin-attacker` persona): set `AdbBridge.Enabled=true`, point `ExecutablePath` at an attacker binary, and set `ExecutableSha256` to that *same* binary's own hash — the "pin" is self-consistent by construction since the attacker controls both fields. The bridge arms with an attacker binary, and the next legitimately-authorized harness action runs it with Foreman's own trust against a real enrolled phone. The same unconditional-load bug also seeds `CuDriver` from settings with no presence gate (`App.xaml.cs:314`).

This also directly contradicts `SettingsSeal.cs`'s own doc comment, which claims tampering "can be reverted + alerted" and that there is "a SACL write-audit on settings.json" — neither exists in code.

**Fix direction:** check `SettingsStore.LastSealVerdict` *before* wiring any security-relevant subsystem, and on `Tampered`, fail closed on those specific fields (re-apply last-known-sealed values) rather than arming first and notifying second.

### 4.2 Guardian's install-time trust decision can be pointed at attacker-chosen input — **CONFIRMED, personally re-traced**

`Foreman.Guardian.exe --install --foreman <path>` passes that path through with **zero validation** (`Program.cs:27`, `ArgValue("--foreman")`). `GuardianIntegrity.Decide()` (`GuardianIntegrity.cs:30-38`, read directly):

```csharp
if (referenceSigner is null)
    return (true, "reference binary is unsigned (dev build) — signature not enforced.");
```

— returns `Trusted=true` **unconditionally** whenever the reference is unsigned, without even inspecting the subject signer in that branch. An attacker needs no cert theft — just `--foreman <any unsigned file they control>`. `GuardianClientPolicy.CreateForInstall` then **persists** that same attacker-chosen path + hash into `client-policy.json` as the one caller permanently authorized to talk to the elevated, SYSTEM-service Guardian. Exploitation requires the attacker to trigger their own `ShellExecute("runas", ...)` with a forged `--foreman` argument — one UAC prompt for "Foreman.Guardian.exe," a prompt shape Foreman routinely and legitimately asks users to approve elsewhere, priming acceptance.

**Fix direction:** never trust `--foreman` as attacker-suppliable input for a security decision — resolve the reference path independently (invoking process's own verified identity, or a known-install-dir lookup). Separately, `Decide()`'s unsigned-reference branch should not exist as an unconditional-trust shortcut at all.

### 4.3 Unrestricted `report_suspicious_command` flood can evict genuine Critical/High alerts from every operator-visible surface — **confirmed** (subsystem + malicious-harness persona, converging independently)

Any connected harness — even one that fails `CanMutate` — can call `report_suspicious_command` in a tight loop with fabricated `commandLine` text engineered to match a Critical rule; the text is never executed, only pattern-matched, and there is **no rate limit and no `CanMutate` gate** on the base publish (`ForemanMcpTools.cs:304-369`). Every subsystem's alarms (settings tamper, decoy tripwire, log-anchor rollback, sidecar impersonation, Guardian issues) funnel through the *same* `EventBus`, whose history is a plain 1000-item FIFO with **zero severity weighting** (`EventBus.cs`), and `ForemanState`'s alert store evicts the same way. `DashboardWindow`'s live feed further only shows the 50 most recent by timestamp — as few as ~50 flood calls push any older alert, regardless of severity, entirely off screen. `foreman_health`'s green/amber/red status derives from the same evictable store, so it can report green moments after a genuine, still-unresolved Critical fired.

**Fix direction:** per-caller rate limiting at the MCP auth gate covering every tool (not just CuBroker); require `CanMutate` for the base publish; make both eviction policies severity-weighted (never evict an unacknowledged High/Critical ahead of older noise); give the dashboard feed a pinned unacknowledged-Critical/High section immune to `Take(50)`.

### 4.4 Only the sidecar's entry-point `.exe` is integrity-checked and pinned — its DLLs are not — **confirmed**

`SidecarPath()` and `PinBinaryAtRest()` (`ElevatedSidecarController.cs`) name and lock only `sidecar\Foreman.EtwSidecar.exe`. `Foreman.App.csproj`'s `CopyEtwSidecar` target copies the **entire** build output tree into that same folder — confirmed against the actual build: `Foreman.EtwSidecar.dll` (the real managed payload the signed apphost loads via hostfxr/coreclr with no signature check of its own), `Foreman.Core.dll`, and ~10 other same-user-writable dependency DLLs sit completely unprotected next to the pinned exe. A same-user process that overwrites `Foreman.EtwSidecar.dll` gets its own code executed under the admin token the branded UAC prompt grants — neither defense notices.

**Fix direction:** publish the sidecar self-contained + `PublishSingleFile` so all managed code embeds into the one already-checked PE, or extend both the pin and the integrity check to every file under `sidecar\`.

## 5. High Findings

*(Confidence noted; "×N" marks a finding independently reached by N different agents/personas — treat as higher-confidence.)*

- **Android Held actions need only the operator bearer token to approve — no presence tap, unlike Desktop** (`ForemanMcpTools.cs` CuApprove, `App.xaml.cs`). Desktop's INV-16 explicitly survives a stolen operator token; Android's does not — a live security regression relative to the codebase's own stated invariant, on the flagship new feature. *confirmed*
- **Panic-stop can lose a narrow race on Android**: `AdbBridgeExecutor` never checks a halted signal inside its own two-sequential-adb-call sequence (get-state, then the real command); if panic fires in the gap between calls, the state-changing command still runs. Distinct from the already-known batch-loop gap. *confirmed*
- **adb.exe SHA-256 pin has a real, empirically-reproduced TOCTOU via NTFS junctions** ×3 (subsystem + android-focused persona + malicious-harness persona chained into zero-interaction code execution via `cu_status` leaking the exact path). The pin is checked once at construction; every launch re-resolves the path string, and a same-user process can junction-swap the containing directory (no special privilege) to redirect every subsequent launch. *confirmed*
- **Android/ADB bridge Settings changes never reach the running broker/executor** ×3 (app-composition-ui, android-adb-bridge subsystem, android-focused persona spot-check — flagged as "still open" from a prior review). Disabling the bridge or un-enrolling a suspected-compromised device gives a plain "Saved" confirmation while the live bridge keeps honoring the old state until a full restart. *confirmed*
- **WMI creation watcher can fully miss a process that starts and exits inside its ~1s poll window** — no compensating discovery exists; a fast one-shot dangerous command from an adversarial harness can evade command-line heuristics, cred-sweep, and orphan tracking entirely, not just with added latency. *confirmed/likely*
- **Guardian's Authenticode gate never checks certificate revocation** (`WTD_REVOKE_NONE`), both for the runtime publisher check and the install-time LPE self-verify — a revoked signing key is trusted forever. *confirmed*
- **`OsEventLogAvailable` is computed once at construction and never updated** — if OS-log writes start silently failing later (log full, service stopped, or a same-user flood of the Application channel), Setup Health keeps showing green for the rest of the session even though the external anti-rollback witness has gone dark. *confirmed*
- **The external log anchor is only republished at launch/rewrite/rotate/clean-exit, not per-append** — a quiet, long-running session's entire forward progress is covered only by the same-user-forgeable in-file chain; a snapshot-then-restore attack reads as "honest forward progress," not rollback. *likely*
- **Vault's presence prompt never names the origin**, contradicting its own "informed consent / anti-phishing" doc comment — the Windows Hello dialog for a credential release or self-signup reads as generic "Authorize a Foreman security change" with no site named. *confirmed*
- **Decoy tripwire only audits `ReadData`** — deleting or overwriting a bait file is an ordinary same-user file op that permanently and silently blinds it, and `Revalidate()` reclassifies this as benign "reclaimed for real credentials" with no alert. *confirmed*
- **CuBroker's Held-item store grows unbounded** — a throttled or Android-forced-Held submission is never pruned; a CU-driver-authorized harness (a normal config, not a bypass) can OOM-crash `Foreman.App` itself, and nothing relaunches it. *confirmed/likely*
- **Auto-approved `logcat` gets zero pre-execution scrutiny and leaves zero durable trace** — no Android case in the fast-path heuristics, a default confidence-1.0 Allow that never escalates to deep judge, an unfiltered device-wide dump, and no EventBus publish for any executed observe-only action. *confirmed*
- **Temporal-anomaly tagging false-positives "monotonic-clock-regressed" on almost every restart** — the write-time check lacks the session-boundary gate its own read-time `Verify()` equivalent has. *confirmed*
- **The auditpol-ownership marker has no ACL hardening**, trusted on bare `File.Exists` — a same-user process can forge or erase it, making Foreman wrongly enable or disable a machine-wide audit policy it never owned. Notably, the sibling Guardian `ProgramData` folder *is* correctly hardened — the team knows the pattern, just didn't apply it here. *likely*
- **Release workflow installs Inno Setup via unpinned Chocolatey** immediately before building the installer that signing and attestation subsequently validate — every other tool in the same workflow is SHA-pinned per the project's own stated rationale; this one isn't, and a compromise here would be validly signed and truthfully attested (attestation proves *this workflow* built it, not that the build tool was clean). *likely*

## 6. Medium Findings

- `FalsePositiveFilter`'s process-name suppression is now **dead code** — the 2026-06-16 CRITICAL fix gated it to severity < Medium, but all 88 current rules are Medium+. Its `Info` fail-open default plus no load-time severity validation means a future rule with a *misspelled* severity string would silently reopen the identical bypass shape (`PatternRule.cs`).
- `ScanRepoForAgentConfig` is the one MCP tool with **no CallerScope check at all** — any authenticated (including narrowly-scoped) harness can scan an arbitrary absolute path.
- Launcher-hygiene suppression marker is unanchored to the actually-invoked script — a decoy substring anywhere in the raw command line can suppress a real `win-002` PowerShell-bypass alert.
- `VaultResolver`'s three distinct failure-reason strings ("not found" / "wrong origin" / "not authorized") let a caller distinguish "credential exists" from "doesn't," contradicting its own documented no-existence-oracle guarantee.
- `KillGuard`'s never-kill set was never extended to the two new Build Week executables (`Foreman.CuSidecar.exe`, `Foreman.CuPilot.exe`).
- A failed Guardian upgrade can strand a rolled-back service pinned to the wrong Foreman hash (policy file is written before the point of no return, and isn't rolled back with the binary on failure).
- Guardian's publisher-signed pinning is tied to an exact certificate **thumbprint**, not a renewal-stable identity — the first legitimate cert renewal (once signing ships) breaks every subsequent release until a manual re-pin.
- Guardian's pipe is single-instance with no per-request timeout — any same-publisher-signed caller can permanently wedge it, silently downgrading every future caller to the unprotected local path.
- The `SealSettings` wire protocol has presence-gated "weakening action" fields that are **implemented on neither end** — the SYSTEM guardian adds no independent check for this operation beyond client identity.
- SetupHealth has **no row at all** for the event-log integrity subsystem's own state (Verify()/AnchorPolicy outcome) — a rollback/forgery notice detected at boot leaves no persistent trace on the one screen meant to answer "is everything OK."
- Setup Health tab can freeze the WPF UI thread for up to ~2.5s when the Guardian pipe is slow (synchronous IPC on the UI thread).
- The android-bridge's device-enrollment membership check is case-insensitive, but the raw caller-supplied casing (not the canonical enrolled value) is what's actually forwarded to `adb -s`.
- `CuBroker.Claim()` never re-validates Android device enrollment at delivery time, unlike Desktop/Browser's explicit re-gate blocks; and `cu_complete_action` isn't modality-scoped like `cu_poll_actions` is, letting a browser-scoped identity race-overwrite an in-flight Android action's recorded outcome.
- The TOCTOU-vulnerable decoy-paths handoff to the elevated sidecar is a plaintext temp file with no path validation, in a window bounded by UAC-approval latency.
- CODE_SIGNING.md — the doc specifically about verifying a download — never mentions `gh attestation verify`, the one check an attacker who merely controls the distribution channel can't forge.
- `release.yml` has no guard preventing an already-published version tag's assets from being silently rebuilt from a different commit.
- `CuStatus` and `CuBroker.CanDrive` have two smaller scoping gaps: the adb executable path/enrolled serials leak to any caller, and a harness literally named `"operator"` would get unconditional driver authority (currently dormant — no minting path produces that id today).
- Broker post-panic bookkeeping can mislabel a completed Android action as "Rejected — halted by panic" when it actually ran to completion on the phone.
- CU approval cards render every modality identically — the one on-screen hint ("a desktop action also needs a Windows Hello tap") implies Desktop is the *stricter* case, when Android/Browser get zero presence verification at all; the status text says "complete any Hello prompt" even for rows where no prompt will ever fire.
- A Held computer-use action produces **zero passive signal** anywhere in the app (no toast, no tray-color change, no tab badge) — the only way to notice one is to proactively open Approvals.
- Toast notifications title any `Severity.High` event "Critical Alert" — identical wording to a genuine Critical, diluting the word before the operator decides whether to open it.
- Game Mode **ships enabled by default** with `AllowCriticalBreakThrough=false` by default — every severity, including Critical, is silently withheld for the duration of any fullscreen/presentation state unless the operator finds an indented, unchecked sub-checkbox.

## 7. Low Findings (terse)

- `PatternRule.FalsePositiveTags` is parsed from every rule but consulted nowhere — vestigial.
- `data/patterns/*.json` has silently drifted out of sync with the live `src/Foreman.Core/patterns/*.json`, contradicting `CONTRIBUTING.md`'s sync instruction; dead and unenforced.
- Dashboard's Settings tab is the only tab never refreshed on tab-show, making `SettingsView.RefreshState()` dead code.
- `App.OnExit` never disposes the desktop-CU sidecar controller or pilot-channel controller (mitigated by their own parent-exit polling — not an orphan-process bug in practice).
- `actions/upload-artifact` is still pinned to a node20-runtime release while sibling actions were bumped to node24 (dormant until signing is enabled).
- `HarnessClassifier` is pure exe-basename matching with no path/hash check — a renamed harness silently loses classification (likely an accepted trade-off; the project explicitly avoids hardcoded binary rosters elsewhere).
- Decoy read-audit's `ExpectedReaders` allowlist is dead code for 7 of 8 canonical decoy kinds (only `.npmrc` is ever actually SACL'd).
- No operator signal when tracked-decoy coverage silently shrinks (`Revalidate()` only runs from the Settings-save handler).
- Decoy watcher starts *after* the SACL ACE goes live — events in that startup gap are lost, never backfilled.
- SetupHealth shows green "Ok" for decoy read-auditing despite its own code comment admitting a connected sidecar doesn't prove events are actually flowing.
- No on-device smoke test exercises the Android bridge's approve→execute→panic chain the way the Desktop path has one.
- `SseSessionManager.MatchesHarness` is documented "never for authorization" but is used exactly that way (low impact: only name/version/capability-flags exposed).
- No operator signal when the Held CU queue balloons from a throttled/misbehaving driver.
- `ReportSuspiciousCommand`'s free-text parameters have no length cap, unlike every other free-text MCP parameter in the file (not exploitable — regex timeouts bound it — just an inconsistency).
- CU approval card's argument preview truncates at 240 characters in low-contrast styling with no "view full" affordance.

## 8. Attack Chains (the distinctive red-team output — narrative, not a checklist)

**The settings-tamper-to-ADB-hijack chain** (§4.1 root cause, Android consequence) is the sharpest: an attacker who never touches Foreman's MCP server at all — just a plain-text edit to a file their own user account already owns — can arm the Android bridge with their own binary, self-consistently "pinned," and have Foreman's own elevated trust launch it against a real enrolled phone the next time *any* legitimately-authorized harness issues an ordinary approved action. The tamper notice fires, but only after the bridge is already armed, once per session, dismissible.

**The vault-memory chain** (same persona): the master password and every decrypted secret sit as plain managed `System.String`/`byte[]` in `Foreman.App`'s own process memory for the whole unlocked session — `VaultDocument.cs`'s own doc comment already admits this is an open limitation. A co-resident, unprivileged process needs nothing more than Task Manager's built-in "Create dump file" to string-scan past the AES-256-GCM+Argon2id+DPAPI envelope entirely, because none of that protects data already decrypted and resident in the reader's own accessible memory.

**The Android zero-interaction RCE chain** (malicious-MCP-harness persona): `cu_status` leaks the exact `adb.exe` path to any caller with no gate → the junction-swap TOCTOU (§5) redirects it → a *read-only, observe-only* Android verb like `screenshot` (which skips the Held/approval gate entirely, by design, because it's "just observation") auto-executes the swapped binary as a child of `Foreman.App` itself. The payload then runs outside every AI-harness process tree Foreman's own command-heuristic/WMI monitoring polices, laundering execution through — and evading — the tool meant to catch exactly this. Three independent things had to individually be true for this chain to close (leak, TOCTOU, observe-only-skips-gating) — each is fixable alone, and any one fix breaks the chain.

**The alert-flood-to-blackout chain** (§4.3, extended): the same unthrottled `report_suspicious_command` flood that evicts alerts can, via `cu_submit`'s unbounded Held-item accumulation, escalate to OOM-crashing `Foreman.App` entirely — taking down the tray, the MCP server, and the sidecar supervisor with it, with no Guardian auto-relaunch. An attacker inside Foreman's own mediation surface, using only documented tools, can produce an unattended, indefinite monitoring blackout.

**The build-pipeline chain** (supply-chain persona): unpinned Chocolatey → unverified Inno Setup compiler output → validly SignPath-signed (SignPath signs bytes, not intent) → checksums generated over the same tampered bytes → attestation truthfully proving *this compromised workflow run* built it. Every documented verification mechanism can be individually satisfied by a compromise that happens upstream of all of them.

**The human-factors chain** (operator-coercion persona): CU approval cards render every modality identically, with copy that specifically calls out Desktop's presence tap and says nothing about Android/Browser having none; the status line says "complete any Hello prompt" even when no prompt will fire; a Held item generates zero passive signal until the operator proactively opens Approvals; and Game Mode ships on by default, silently withholding even Critical alerts during any fullscreen state. None of these require a code exploit — they compound into exactly the rubber-stamping conditions a real attacker (or a rushed operator) would want.

## 9. Prioritized Fix Plan

**P0 — before any further public/judged exposure:**
1. Settings-tamper fail-closed (§4.1) — *medium effort*, highest leverage: closes the presence-lock bypass and the ADB-hijack chain in one fix.
2. Guardian install-time trust bypass (§4.2) — *small effort*: stop trusting `--foreman` as attacker input.
3. `report_suspicious_command` rate-limit + severity-weighted eviction (§4.3) — *medium effort*.
4. Sidecar directory-wide integrity (§4.4) — *small-medium effort*: self-contained single-file publish is the simplest close.
5. Android Held-action presence tap parity with Desktop (§5) — *small effort*, high symbolic + real value given this is the showcase feature.
6. adb.exe junction-TOCTOU re-verification before every launch (§5) — *small effort*, closes 3 independently-found chains at once.
7. Android bridge Settings live-reapply (§5) — *medium effort*: found 3 times independently; a revocation control that doesn't revoke is worse than none.

**P1 — next:**
- Guardian certificate revocation checking; OS-event-log liveness re-probing; per-append external anchor refresh; temporal-anomaly session-boundary gate; vault presence-prompt origin naming; decoy Delete/WriteData auditing; CuBroker Held-item backpressure + Guardian auto-relaunch on crash; `logcat` scrutiny + durable trace; auditpol-marker ACL hardening; pin Inno Setup in CI; panic-stop per-tick check inside `AdbBridgeExecutor`; Android delivery-time re-gate in `Claim()` + modality-scope `cu_complete_action`.

**P2 — QOL and the rest of Medium/Low:** everything in §6/§7, plus the human-factors UI work in §8 (modality-distinct approval cards, a passive Held-queue signal, severity-correct toast titles, Game Mode default). None are individually urgent, but several are cheap and the alert-fatigue cluster compounds with the P0/P1 security items if left alone — an operator trained to rubber-stamp uniform-looking approval cards is a weaker backstop for every other fix on this list.

---
*Methodology note: findings above were produced by 11 subsystem deep-read agents and 5 adversarial-persona agents (16 total, all completed successfully), plus a partial adversarial verification pass (15 functional-bug refutation checks, ~43 security findings through a 3-vote panel) that was cut short by a tooling failure in the aggregation step, not a content failure — no agent's analysis was lost, only the ability to attribute individual verify verdicts back to specific findings. The two highest-severity claims were independently re-traced against the current source by the report author before inclusion.*

## 10. Remediation follow-up (2026-07-22)

The original findings above describe snapshot `c5fd504` and are retained as the audit record. The following fixes were applied in the subsequent working tree and regression-tested before hand-off:

- **Settings tamper now fails closed before composition.** `SettingsStore.Load()` never returns a settings object whose security projection failed its seal. It restores a separately sealed last-known-good snapshot before `App.OnStartup` wires any subsystem, quarantines the attempted file, and uses safe defaults when no verified recovery exists.
- **Guardian install no longer accepts a caller-supplied `--foreman` path.** The app passes its live PID and the elevated Guardian resolves that image. After round-three review, unsigned LocalSystem installation is refused outright: neither a missing HKLM root nor an argv development flag can establish trust. A verified same-publisher pair may establish the root on first signed install; publisher policy cannot be downgraded to path/hash mode, and uninstall clears the HKLM anchor.
- **Suspicious-command alert minting is bounded.** Verdicts remain available to callers, but operator-visible publication now requires a mutation-capable (non-peer-mismatched) caller and is capped per caller. The EventBus and MCP alert store evict acknowledged/lower-severity noise before unresolved High/Critical evidence, and the dashboard pins unresolved High/Critical cards ahead of ordinary recency.
- **Elevated sidecar payload integrity is complete.** Shipped builds were already published as one self-contained signed executable; release validation now explicitly rejects any neighbouring sidecar payload. Framework-dependent development builds now hold write/delete-denying handles on every staged sidecar file and verify the directory snapshot before elevation, rather than locking only the apphost EXE.
- **Android Held approvals have presence parity.** Both MCP and in-app approval paths require a fresh Hello/FIDO2 verification for Held Android actions, matching Desktop's bearer-token-resistant approval rule.
- **ADB junction redirection and panic-gap paths are closed.** `AdbProcessRunner` launches the final path resolved from the already hash-checked, pinned file handle, so swapping a parent junction cannot redirect `Process.Start`. The executor also re-checks panic after `get-state` and immediately before the device action.
- **ADB configuration changes apply live.** Save now revokes all non-terminal Android actions, clears device authority, stops/disposes the old pump and binary lease, then arms the newly saved binary/device set. Disabling or un-enrolling therefore takes effect before the Settings view reports success; stale approved actions must be re-submitted.

The auditpol ownership-marker High finding was also addressed in the same working tree with a short-lived, ACL-hardened, atomically written ownership lease and ownership-safe rollback/disable behaviour.
