# TraceBrake Live Review (2026-09-04)

**Method:** first review conducted against the RUNNING instance via TraceBrake's own MCP surface, as a connected
`claude-code` harness, rather than by reading code alone. Findings marked LIVE were reproduced by calling the product.

**State at review:** branch `codey/installer-release-readiness`, 54 files uncommitted (+2391/-651). Running instance
reports `status: red`, 28 active alerts, 421 monitored processes, 1 pending Ask-Harness request, version 0.1.0.

---

## 1. Headline

Three things matter, in order.

**You currently cannot validate this product.** Bitdefender is persistently blocking `Foreman.Core.Tests.dll`, so
the largest suite (~1067 tests) will not run at all. Five suites pass (426 tests); the biggest one is dark. This is
the third Bitdefender incident on this file and the first that is a hard, repeating blocker rather than a one-off
quarantine.

**A finding now in its fourth consecutive audit is confirmed live, and is worse than previously described.**
`scan_repo_for_agent_config` is not merely unscoped: it reads paths the caller's own declared policy denies, and
leaves no audit record of any kind.

**2391 lines of uncommitted, unaudited work are running as your live security monitor**, with the largest test
suite unable to run against them.

---

## 2. Test status (ground truth)

| Suite | Result |
|---|---|
| Foreman.Core.Tests | **BLOCKED — cannot build** |
| Foreman.McpServer.Tests | 238 passed |
| Foreman.Guardian.Tests | 28 passed |
| Foreman.Monitor.Tests | 100 passed |
| Foreman.Vault.Tests | 53 passed |
| Foreman.Platform.Linux.Tests | 7 passed |

Core fails with `MSB3021: Unable to copy file ... Access to the path ... is denied`. The file exists (422 KB) but is
held by another process; opening it returns "being used by another process", the `bin` copy never lands, and
Bitdefender is running `bdredline` plus five `bdservicehost` instances. Retried in **both Release and Debug** with
identical failure, so this is persistent, not a transient scan lock.

Net: 426 tests green, ~1067 unverifiable.

---

## 3. LIVE findings

### 3.1 scan_repo_for_agent_config is an unlogged, policy-bypassing filesystem oracle — HIGH

Reported in the 2026-07-21, 07-22 and 07-25 audits. Now reproduced live, and the live behaviour is worse than the
static reads suggested. Three separate defects compound:

1. **No caller scoping.** As `claude-code` I scanned `C:\Users\AxelW\AppData\Local\Perplexity`, entirely unrelated to
   my working directory. Returned `scanned: true` with results.
2. **It ignores the caller's own filesystem policy.** `get_my_permissions` returns
   `fileSystem.deniedPaths` including `C:\Windows\*`, `C:\Windows\System32\*`, `%USERPROFILE%\.ssh\*`,
   `%USERPROFILE%\.aws\*`, `%USERPROFILE%\.gnupg\*`. I then scanned `C:\Windows\System32\drivers\etc` — squarely
   inside a denied pattern — and got `scanned: true, verdict: clean`. No refusal, no downgrade.
3. **Zero audit trail.** Neither scan produced any event at any severity. `list_recent_events` after both calls shows
   nothing between them; the newest entries remain unrelated PowerShell alerts from minutes earlier.

Why it matters: the denied-path list is precisely where the decoy credentials live (`.ssh`, `.aws`, `.gnupg`). A
narrowly-scoped token (browser-extension, liveweave) gets the same reach. So a security product ships a tool that
reads what it tells the caller it may not read, and records nothing.

**Invariant:** a tool must never grant a caller access the caller's own policy denies, and any filesystem read on a
caller's behalf must leave a durable record.

**Fix:** gate the tool to operator scope or to the caller's resolved working tree; consult `fileSystem.deniedPaths`
before scanning and refuse or redact on match; publish an InfoEvent per invocation with caller identity and path.

**Proving test:** as a non-operator harness, `scan_repo_for_agent_config` against a path matching a denied pattern
must return refused, and an event naming caller and path must exist afterward. Both assertions fail today.

### 3.2 The same file enforces scoping correctly elsewhere — the inconsistency IS the finding

`get_audit_route(targetHarnessId: "codex")` from the `claude-code` token was correctly refused:
"You can only resolve the audit route for your own harness." That is good design, and it blocks the audit-topology
reconnaissance an attacker would need. Credit where due.

But it sits in the same tool surface as an unscoped filesystem reader. This is the codebase's recurring signature:
the invariant is enforced on the path someone thought about, and absent on its sibling. Worth an explicit sweep for
"which tools consult caller scope, and which do not," rather than fixing scan_repo_for_agent_config alone.

### 3.3 Status is red because of its own auditor — MEDIUM (QOL / alert fidelity)

All High events are this Claude Code session's PowerShell (`win-001` encoded command, `win-002` execution-policy
bypass), escalating `claude-code` to `[ALARM]`. 28 active alerts, status red, driven by the tool that was asked to
review it. Detection is behaving correctly by its own rules; the problem is that routine agent operation saturates
the operator's top-level signal. A product whose thesis is "smarter and less annoying than BitDefender" currently
shows red for its own supervisor doing its job.

### 3.4 No clean shutdown path, so every restart forges a tamper signature — MEDIUM

`CloseMainWindow()` times out (tray app, no main window), forcing a kill, after which the next start logs a
**Critical**: "previous TraceBrake instance was terminated WITHOUT a clean shutdown or crash record — the signature
of a forced kill." Every legitimate scripted restart manufactures a false tamper Critical. For a tool that exists to
distinguish real tampering from routine activity, its own restart path is indistinguishable from an attack.

**Fix:** a `--shutdown` flag or IPC quit command that writes a clean-exit record.

### 3.5 Guardian unreachable at launch, every launch — MEDIUM

Each start logs: "settings.json carries a guardian-backed seal but the guardian service was unreachable at launch,
so its security posture could not be verified." This is the boot-race predicted in the round-3 report (P0-3b). It
currently degrades to a Medium notice rather than the destructive quarantine path, which is the correct behaviour,
but it fires on every launch and so trains the operator to ignore it.

### 3.6 Run-key auto-start silently reverted, twice — MEDIUM

`HKCU\...\Run\TraceBrake` was restored, then removed again. OneDrive, Turtle Beach, Comet, Edge and Chrome entries
all persist, so the key is healthy and only TraceBrake's entry vanishes. Bitdefender ATD rollback is the likely
cause. Net effect: **auto-start does not work**, silently, on a security product.

---

## 4. Unaudited surface

Branch `codey/installer-release-readiness`: 54 files, +2391/-651, uncommitted, never audited, currently running.
It touches security-critical areas — `SettingsSeal`, `SettingsStore`, `EventLogStore`, `McpAuthToken`, `CallerScope`,
`CuBroker`, `AeadVaultStore`, `DepositCrypto`, `VaultCrypto`, `KillGuard`, `HarnessCapabilityPolicy`,
`FalsePositiveFilter`, `GuardianSettingsSealer`. Three nullable warnings survive the build: `DepositCrypto.cs:63`,
`VaultCrypto.cs:58`, `ForemanMcpTools.cs:742` (a possible null `requestId` into `ReplyToAskHarnessRequest`, which is
the Ask-Harness reply path and therefore worth a look on its own).

None of this has been reviewed, and the suite that would cover most of it cannot run.

---

## 5. What to do, in order

1. **Add the Bitdefender exclusion** for `W:\TOOLS\Foreman` covering **both** Antivirus and Advanced Threat Defense.
   ATD is doing the Run-key rollback, so an antivirus-only exclusion will not fix auto-start. This unblocks the Core
   suite and the auto-start regression together. Everything else is gated behind it.
2. **Run Foreman.Core.Tests** once unblocked. Do not trust the branch until it is green.
3. **Fix scan_repo_for_agent_config** (3.1) — scope it, make it honour `deniedPaths`, and log every invocation.
4. **Sweep the tool surface** for caller-scope consistency (3.2) rather than patching the one tool.
5. **Add a clean-shutdown path** (3.4) so restarts stop forging tamper Criticals.
6. **Review the uncommitted branch**, or commit it so it is at least a reviewable baseline.

---

*Reviewed live against the running instance via the `foreman_*` MCP surface. Findings in section 3 were reproduced by
calling the product, not inferred from source.*
