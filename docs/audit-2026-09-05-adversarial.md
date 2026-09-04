# TraceBrake Adversarial Audit (2026-09-05)

**Scope:** the whole tree at `codey/installer-release-readiness` (11 commits ahead of `origin/main`), including the
28 uncommitted entries currently in flight, plus live probing of the running instance via its own MCP surface.

**Posture:** adversarial. The goal was to find what is broken, not to confirm that it works. Findings marked LIVE were
reproduced against the running product. Findings marked REPRO were reproduced on the command line and the exact
failing line is named. Everything else is a code read and is labelled as such.

**Method note:** this audit deliberately checks the *previous* audits' findings again rather than only hunting new
ones. A finding that survives four reports is worth more than a fresh nitpick.

---

## 1. Verdict

Three sentences.

**You still cannot validate this product, and as of this branch you cannot validate it in a second, independent way.**
The Bitdefender block on `Foreman.Core.Tests` is now five days old, and the new mandatory test entrypoint fails on
every PowerShell installed on this machine before it runs a single test.

**A finding now in its fifth consecutive audit is still open, still unlogged, and was re-triggered live during this
audit.**

**The new coordination subsystem is well built and reproduces the codebase's single most persistent defect:** a
read tool that any authenticated caller can point anywhere, which leaves no record.

---

## 2. Credit where it is due

Calibration matters, so read the findings against this.

The uncommitted work is the strongest security change in the branch. Splitting MCP sampling output into
`SampledCandidateText` as **non-terminal candidate evidence** closes a real hole: sampling previously moved an
Ask-Harness request to `Answered`, which meant a model-generated string could satisfy a safety prompt addressed to a
harness. `RecordSampledCandidate` never advances the lifecycle, the first candidate wins, and the correlation check
(`res.RequestId == requestId`) rejects mismatched round-trips. That is the right fix.

`ResolveCompanionMutationIdentity` pins identity to the authenticated caller and explicitly refuses to let an
**operator** token forge another harness's state. `RepoIntentLease.LeaseCapability` and `IdempotencyKey` are
`[JsonIgnore]` and non-positional so record `ToString()` cannot leak them. `CapabilityMatches` is constant-time. The
33 new tests are adversarial rather than confirmatory: `OperatorCannotForgeAnotherHarnessPetOrLeaseState`,
`PetCheckIn_PeerMismatchFailsClosed`, `CapabilityIsNotPrintedOrSerializedWithLeaseOrResult`,
`SameWorktreeConflictsEvenWhenCallersClaimDifferentRepositoryKeys`. `docs/tracebrake-companion.md` lists eleven
production gaps honestly, including that lease capabilities are model-visible.

The solution also builds clean: **0 warnings**, one error, and that error is the Bitdefender block. The three
nullable warnings flagged in the 2026-09-04 review are gone.

Nothing below contradicts any of that. The findings are about what sits next to the good work.

---

## 3. Blocking findings

### H1. The mandated test entrypoint cannot run on this machine at all. REPRO

`scripts/Invoke-DotNetTests.ps1` is now the only documented way to run tests. It was substituted into
`.github/workflows/ci.yml`, `.github/workflows/release.yml`, `docs/release-checklist.md`, `CONTRIBUTING.md`,
`.github/PULL_REQUEST_TEMPLATE.md`, and a tasks `display` entry, all replacing `dotnet test Foreman.slnx`.

Two independent defects, either of which alone is blocking:

**1. `pwsh` is not installed.** Verified: `Get-Command pwsh` returns nothing and
`C:\Program Files\PowerShell\7\pwsh.exe` does not exist. This box has Windows PowerShell **5.1.26100.9223** only.
Every command in the docs begins `pwsh -NoProfile -File ...`, so the release checklist's first Required step is
unexecutable as written by the person who owns the release.

**2. The script fails on 5.1 before running any test.** Under `powershell.exe`:

```
Invoke-DotNetTests.ps1 : Cannot convert 'System.String[]' to the type 'System.String'
required by parameter 'ChildPath'. Specified method is not supported.
```

Traced to the exact line, first loop iteration:

```powershell
$projectResults = Join-Path $resultsRoot $projectName    # line 83
```

`$projectName` is `$project.BaseName`, so `$project` is a collection, so `$selectedProjects` holds the whole
`FileInfo[]` as a single element. The cause is the `@( if (...) { $discoveredProjects } else { ... } )` construct on
line 62: PowerShell 7 enumerates the array out of the `if` statement, Windows PowerShell 5.1 does not.

This is **not** the `-ProjectName` filter bug reported yesterday. It fails identically with no arguments at all.
The filter is fine; the script is PS7-only by accident.

CI is unaffected because `windows-latest` ships `pwsh`. That is precisely the problem: **CI green will no longer
mean the developer can reproduce it.** Every local verification path in the release checklist has been quietly
routed through a shell that is not installed.

**Invariant:** a test entrypoint referenced by the release checklist must run on the shells the project actually
supports, and the supported set must be stated.

**Fix:** replace line 62 with an explicit assignment that forces enumeration (`$selectedProjects =
@($discoveredProjects)` in the empty branch, `@(foreach ...)` in the other), or index the loop. Then decide
explicitly: either require PS7 and say so in `CONTRIBUTING.md` with an install line, or keep 5.1 compatibility and
change every invocation to `powershell`. Do not leave it implicit.

**Proving test:** `powershell -NoProfile -File .\scripts\Invoke-DotNetTests.ps1 -Configuration Release` reaches at
least the first `Testing <project>` line.

---

### H2. `Foreman.Core.Tests` has been unbuildable for five days. LIVE

```
CSC : error CS2012: Cannot open
'W:\TOOLS\Foreman\tests\Foreman.Core.Tests\obj\Release\net10.0\Foreman.Core.Tests.dll'
for writing -- Access to the path ... is denied.
```

Re-confirmed today after the exclusion was added. Previously confirmed across Release, Debug, and a full `obj`/`bin`
clean, with the DLL going from present (422 KB) to absent, and with no `testhost`/`vstest` process or loaded module
holding it. The compiler write itself is being denied, which is behavioural interdiction, not a scan lock.

The exclusion has not taken effect for this path. Most likely one of: it covers Antivirus but not **Advanced Threat
Defense** (separate exclusion lists, and ATD is the behavioural engine that also performed the Run-key rollback in
finding M2); it needs a Bitdefender restart; or it was added as a file rather than a folder exclusion. If ATD will
not accept a folder exclusion, the fallback is to restore the quarantined item and choose "add to exceptions" from
the quarantine entry, which whitelists the detection rather than the path.

**I have not touched and will not touch the AV configuration.** This one is yours to make.

**Consequence:** approximately 1,167 tests, the largest suite and the one covering `SettingsSeal`, `SettingsStore`,
`EventLogStore`, `McpAuthToken`, `CallerScope`, `KillGuard`, `AeadVaultStore`, and `VaultCrypto`, have not run
against this branch. 426 tests pass across the other five suites.

---

## 4. Security findings

### H3. `scan_repo_for_agent_config` reads paths the caller's own policy denies, and logs nothing. LIVE

**Fifth consecutive audit** (2026-07-21, 07-22, 07-25, 09-04, and now). Re-triggered live during this audit as the
`claude-code` harness.

My own `get_my_permissions` returns:

```
fileSystem.deniedPaths: ["C:\\Windows\\*", "C:\\Windows\\System32\\*",
  "%USERPROFILE%\\.ssh\\*", "%USERPROFILE%\\.aws\\*", "%USERPROFILE%\\.gnupg\\*"]
```

I then called `scan_repo_for_agent_config("C:\Windows\System32\drivers\etc")` and got:

```json
{"scanned": true, "path": "C:\\Windows\\System32\\drivers\\etc",
 "findingCount": 0, "highestSeverity": "none", "verdict": "clean"}
```

No refusal, no downgrade. Then `list_recent_events(limit: 5)` returned a newest event timestamped **14:45:24**,
which is *before* the scan. The scan produced no event at any severity.

The denied list is exactly where the decoy credentials live. A narrowly scoped token gets identical reach. A
security product ships a tool that reads what it tells the caller it may not read and records nothing.

**Invariant:** a tool must never grant a caller access the caller's own policy denies, and any filesystem read
performed on a caller's behalf must leave a durable record.

**Fix:** consult `fileSystem.deniedPaths` before scanning and refuse on match; scope non-operator callers to their
resolved working tree; publish an `InfoEvent` per invocation naming caller and path.

**Proving test:** as a non-operator harness, a scan of a path matching a denied pattern returns refused, and an
event naming caller and path exists afterward. Both assertions fail today.

---

### H4. `get_repo_coordination_status` is a new, unscoped cross-harness probe. Code read

`src/Foreman.McpServer/ForemanMcpTools.Companion.cs:290`. The only authorization check is
`if (!caller.CanMutate)`, which merely proves the caller is *some* authenticated harness. There is no requirement
that the caller holds a lease at that root, that the root is inside its working tree, or that it has ever registered
anything.

The selection filter in `RepoCoordinationBroker.Snapshot` is a **disjunction**:

```csharp
.Where(l => SameRoot(l.RepoRoot, root)
            || string.Equals(l.RepositoryKey, repoKey, StringComparison.OrdinalIgnoreCase)
            || l.Resources.Intersect(resourceScopes, StringComparer.OrdinalIgnoreCase).Any())
```

so any one of three caller-controlled inputs matches. Resource ids are low-entropy canonical strings by design
(`port:tcp:localhost:5432`, `device:adb:serial`), which makes them trivially enumerable. A caller who guesses one
gets `foreignLeaseSignals` for every harness holding it: `leaseId`, `harnessId`, `mode`, **`paths`**, **`resources`**,
`expiresAt`.

It then pivots. `Snapshot` deliberately re-adds leases that *conflict* with a selected lease
(`relatedIds`), including leases at repo roots the caller never named, and those flow into the same foreign
projection. One guessed port id surfaces other checkouts.

Two smaller leaks ride along: `leaseCount` and `conflictCount` are computed from the **unredacted** snapshot, so a
non-operator learns the true global count for any probe; and the tool emits no event, so the probe is invisible.

The redaction itself is good. That is the trap: `RepoStatus_MinimizesForeignLeaseDetails` passes, and minimization
is not authorization. The subsystem enforces caller scope correctly on every *write* path
(`ResolveCompanionMutationIdentity`, and `get_audit_route` refusing cross-harness resolution) and omits it on the
read path. This is the codebase's recurring signature, reproduced in code written **after** the audits that named
it.

**Invariant:** a cross-harness read must be justified by the caller's own scope, and must be logged.

**Fix:** require that the caller either holds a lease in the queried collision domain or is the operator; drop
`leaseCount`/`conflictCount` to the visible count for non-operators; publish an `InfoEvent` naming caller, root, and
result size.

**Proving test:** harness A registers a lease with resource `port:tcp:localhost:5432`; harness B, holding no lease,
calls `get_repo_coordination_status` with an unrelated `repoRoot` and that resource, and must receive an empty
projection plus an audit event. Today it receives A's lease.

**Do not fix this file yourself.** Codex owns it and is mid-write. See section 7.

---

### M1. Routine agent operation saturates the alert store in about half a day. LIVE

`foreman_status`: `status: red`, **242 active alerts**, 451 monitored processes, uptime 10,996s (3h03m). That is
**79 alerts/hour**. `MaxAlerts` is 1000, so ordinary use fills the store in roughly **12.6 hours**, after which
eviction begins discarding real findings. The alert-flood eviction path was already flagged CRITICAL in the
2026-07-21 audit. This is the live proof that the flood needs no attacker.

Sampling a 100-second window, 14:43:45 to 14:45:25, gives eleven High and Medium alerts. Every one is this Claude
Code session's own PowerShell:

```
[win-001] PowerShell encoded command: ...powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand ...
[win-002] PowerShell execution policy bypass: ...powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass ...
```

That is verbatim how the harness invokes PowerShell. The detector fires on every tool call, roughly one alert per
nine seconds.

At 12:04 it reached the product's top tier:

```
Critical | Foreman.Behavior | [EMERGENCY] claude-code - 10 alert(s), 2 rule(s),
          trigger: PowerShell execution policy bypass
```

**That is the only Critical in the visible log, and it is a false positive on the supervising agent.**

There is a precise, provable sub-defect here. `get_my_permissions` returns
`launcherPolicy.launcherSuppressedRuleIds: ["win-002"]`. The suppression for win-002 exists and **is not engaging**
for this harness's own launcher-originated PowerShell. Separately, win-001 has no suppression at all despite
encoded-command invocation being the harness's standard form.

Worth naming the irony plainly: win-001 is the same heuristic class Bitdefender used to false-positive on
TraceBrake's own build output in finding H2. The product's stated thesis is that it is smarter and less annoying
than Bitdefender.

**Fix, in order:** (a) find why `launcherSuppressedRuleIds` does not suppress win-002 for launcher-parented
processes, since the mechanism already exists; (b) add win-001 to the launcher suppression set, or match on the
`-NoProfile -NonInteractive -NoLogo -EncodedCommand` launcher signature; (c) collapse repeated identical
rule/harness pairs into one alert with a count, so escalation counts distinct behaviour rather than tool calls.

---

### M2. The ETW sidecar is not running, so decoy read-auditing is disarmed, and nothing says so. LIVE

Process check: `Foreman` (pid 24492) and `Foreman.Guardian` (pid 6672) are up; **`Foreman.EtwSidecar` is absent**
after three hours of uptime. The sidecar is what arms the SACL watcher, so decoy credential read-auditing is
currently off.

This is the exact condition root-caused on 2026-07-08, and `SidecarSupervisor` plus the liveness/auto-relaunch work
in `a3c84c8` was built to prevent it. Either the supervisor never armed, or it recorded a declined launch and
correctly refuses to retry, or `RunElevated` is opt-out and off. The audit cannot distinguish these from outside,
and **that is the finding**: there is no High or Critical event, and no operator-visible statement, that the
product's decoy tripwire is currently disarmed. The one place where silence is indistinguishable from health is the
tripwire.

**Fix:** surface sidecar state in `foreman_status` as a first-class field, and raise a persistent High notice
whenever decoy auditing is configured but unarmed. Distinguish "declined by operator" from "crashed and not
relaunched" in the message.

---

### M3. `global.json` pins a feature band that CI does not install. Code read

New untracked `global.json`:

```json
{ "sdk": { "version": "10.0.400", "rollForward": "latestPatch", "allowPrerelease": false } }
```

Both workflows use `actions/setup-dotnet` with `dotnet-version: '10.0.x'`, which installs the newest 10.0 SDK
available. `latestPatch` rolls forward only **within** the 10.0.4xx band. The day .NET ships 10.0.5xx, the runner
installs it, `global.json` refuses it, and CI and the release pipeline both fail with an SDK-not-found error that
looks nothing like its cause.

It works today (10.0.400 is installed locally and is current), which is what makes it a time bomb rather than a
bug.

**Fix:** replace `dotnet-version: '10.0.x'` with `global-json-file: global.json` in both workflows, so one file is
authoritative. Alternatively set `rollForward: latestFeature`, but the single-source version is better.

---

### M4. A tracked workflow now invokes an untracked script. Code read

`.github/workflows/ci.yml` and `release.yml` are **tracked and modified** to call
`./scripts/Invoke-DotNetTests.ps1`. That script and `global.json` are **untracked**. If the workflow changes land in
a commit without them, CI fails immediately on every push.

This is normally a non-issue for one author. With two agents committing to one worktree in parallel it is a live
hazard, and it is exactly the kind of split a partial `git add` produces. `docs/release-checklist.md`,
`CONTRIBUTING.md`, and the PR template have the same coupling.

**Fix:** commit `scripts/Invoke-DotNetTests.ps1` and `global.json` in the **same** commit as the workflow and doc
changes, or not at all. See section 7 for who does this.

---

### M5. Injected AGENTS.md instructions run ahead of the shipped tool surface. Code read

`CodexMcpConnector` now writes instructions telling Codex to call `pet_check_in`, `get_repo_coordination_status`,
and `register_repo_intent`. Those tools exist only in uncommitted code. The **running** instance does not expose
them: this session's MCP inventory has no `pet_*` or `*_repo_intent` tool.

So any Codex session that picks up the new AGENTS.md against a released or currently-running TraceBrake is
instructed to call tools that return "Unknown tool". This project has already been bitten by exactly this class once
(the PascalCase/snake_case mismatch that broke Codex's Foreman calls, fixed in `2726421`). There is no capability
negotiation between the text TraceBrake writes into another agent's config and the tool list the server actually
serves.

**Fix:** gate the new instruction paragraphs on server capability, or version the injected block and have the
connector emit only the paragraphs matching the running server's advertised tool list.

Secondary, and worth a decision rather than a fix: the same block instructs Codex to treat the idempotency nonce and
lease capability as sensitive **model-visible** values. `docs/tracebrake-companion.md` gap 10 already acknowledges
this. Handing a bearer capability to a model in plaintext and then asking the model to keep it secret is not a
control. Until the signed host bridge exists, the capability should be treated as public and the security should not
rest on it.

---

### M6. Idle-cleanup asks can no longer resolve themselves, and nothing was added to close them. Code read

`App.xaml.cs` correctly replaces `RecordAskHarnessReply` with `RecordAskHarnessSampledCandidate` in the
`IdleCleanup.PushToOffender` path and in `SafeAsk`. That is the right security change (H2 in section 2).

The consequence was not handled. Idle-cleanup requests previously reached `Answered` via the sampling round-trip.
They now stay `Pending` until the reaper ages them to `Expired`, and `Expired` is logged rather than silently
dropped. So a correct security fix converts a quiet path into a recurring stream of Expired events, feeding directly
into M1.

**Fix:** either have the idle-cleanup detector close its own request when it observes the cleanup actually happened,
or classify auto-generated cleanup asks so their expiry is Info rather than an alert.

---

## 5. Lower-severity findings

**L1. Every MCP tool fails open when the state bag is unwired.** `_state ?? new ForemanState()` appears in more than
20 tools including all eight new companion tools. A misconfigured or partially started server returns `ok: true`
with empty, benign-looking data instead of an error. It is pre-existing and systemic, not new, but
`get_repo_coordination_status` makes it visibly worse: the throwaway state carries a **fresh `brokerEpoch` on every
call**, and callers are told to discard their cursor when the epoch changes. Replace with an explicit
"server not initialised" refusal.

**L2. The test-count floor of 1,167 for `Foreman.Core.Tests` is unverified.** The floor idea is genuinely good and
catches the false-green no-op run the comment describes. But nobody has observed 1,167 on this machine, because the
suite has not run in five days. A static count gives 818 `[Fact]`/`[Theory]` attributes plus 340 `[InlineData]`
rows, so the number is plausible, not confirmed. If it is wrong high, CI fails; wrong low, the floor is decorative.
Confirm it the first time the suite runs.

**L3. `RepoCoordinationBroker.TryNormalizeRoot` rejects any path whose third character onward contains a colon.**
Intended to block alternate-data-stream syntax. On Linux it rejects legitimate paths containing a colon, and
`Foreman.Platform.Linux` is a shipping project. Also, the `\\?\` check is dead code: `StartsWith("\\\\")` already
caught it.

**L4. `ExpireLocked` increments `_revision` once per expired lease.** Pollers doing `sinceRevision` diffing see the
revision move with no observable state change. Cosmetic, but it undermines the cursor contract the response
advertises.

---

## 6. What I could not verify

Stated so this report is not read as more complete than it is.

- **Anything covered by `Foreman.Core.Tests`.** Roughly 1,167 tests over the settings seal, event log store, MCP
  auth tokens, caller scope, kill guard, and vault crypto did not run. H4 and the companion subsystem are covered by
  `Foreman.McpServer.Tests`, which does run.
- **The new coordination tools under live conditions.** They are uncommitted, so the running instance does not
  expose them. H4 is a code read, not a live reproduction.
- **Whether the boot-time Criticals from the 2026-09-04 review (forced-kill tamper signature, Guardian unreachable
  at launch) still fire.** The event log holds 1,000 entries and M1 is filling it at 79 alerts/hour, so the boot
  window is plausibly already evicted. I did not confirm eviction, and I am not claiming those findings are fixed
  or unfixed.
- **The exact PS 5.1 versus PS 7 divergence in H1.** The failing line and the type error are confirmed
  reproductions. The `@( if ... )` enumeration difference is the mechanism I infer from them; a standalone repro of
  that construct did not reproduce it in isolation, so treat the line as certain and the mechanism as likely.

---

## 7. Action plan

Ordered by what unblocks what. Ownership matters because Codex is running concurrently in this worktree
(pid 37412) and owns the entire companion and coordination surface.

### Yours, and everything else waits on it

1. **Fix the Bitdefender exclusion (H2).** Confirm `W:\TOOLS\Foreman` appears under **both** Antivirus and Advanced
   Threat Defense, restart Bitdefender, and if ATD refuses a folder exclusion, whitelist from the quarantine entry
   instead. This unblocks the 1,167-test suite and, since ATD is the likely cause of the Run-key rollback, probably
   auto-start too. I will not change AV settings.

### Mine, safe to do in parallel with Codex

2. **Fix `Invoke-DotNetTests.ps1` line 62 and decide the shell contract (H1).** One-line fix plus a documented
   decision. It touches only `scripts/` and docs, both outside Codex's active files. Then run the full suite and
   confirm or correct the 1,167 floor (L2).
3. **Point the workflows at `global.json` (M3).** Two lines in `.github/workflows/`, no overlap with Codex.
4. **Run `Foreman.Core.Tests` the moment H2 clears** and report the real count. Do not trust this branch until it is
   green.

### Codex's, hand over rather than touch

5. **Scope and log `get_repo_coordination_status` (H4).** Requires the caller to hold a lease in the queried
   collision domain or be the operator; drop the unredacted `leaseCount`/`conflictCount` for non-operators; emit an
   audit event. `ForemanMcpTools.Companion.cs` and `RepoCoordinationBroker.cs` are mid-write.
6. **Commit `scripts/Invoke-DotNetTests.ps1` and `global.json` together with the workflow and doc changes (M4).**
   Whoever commits the workflows commits the script in the same commit.
7. **Gate the injected AGENTS.md paragraphs on server capability (M5).**
8. **Close the idle-cleanup expiry path (M6).**

### Next, once the suite is green

9. **Fix the alert flood (M1).** Start with why `launcherSuppressedRuleIds` does not suppress win-002, since the
   mechanism already exists and is simply not firing. Then add win-001. Then collapse duplicate rule/harness pairs
   so escalation counts behaviour rather than tool calls. This is the single largest gap between what the product
   claims and what it does.
10. **Surface sidecar and decoy state (M2).** A disarmed tripwire must be loud.
11. **Sweep the whole tool surface for caller-scope consistency.** H3 and H4 are the same defect in two places, four
    audits apart. Patching them individually will not stop the third instance. Enumerate every tool, record which
    consults `CallerScope` and which does not, and make the omission a review checklist item.
12. **Fix H3 itself (`scan_repo_for_agent_config`).** Five audits. It is a contained change: honour `deniedPaths`,
    scope non-operators, log every call.

---

*Findings marked LIVE were reproduced against the running instance through the `foreman_*` MCP surface. Findings
marked REPRO were reproduced on the command line with the failing line identified. Everything else is a code read
and is labelled as such.*
