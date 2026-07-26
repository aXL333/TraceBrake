# P0 Fix Brief — Round-3 Audit (for the next fix pass)

> **Implementation status (2026-07-26):** actioned. Each P0 now has sibling-path coverage: whole-tree release
> purity plus runtime manifest verification; unsigned Guardian refusal and downgrade prevention; missing/slow/legacy
> settings recovery; publisher-assigned event provenance and controller-owned UAC timeout; verb/argument-invariant
> card release plus extension and PAN tests; armed-count decoy health plus 4660 deletion correlation; and
> main-ancestry/annotated-tag release gating. The source audit remains unchanged below so the original claims remain
> reviewable.

Source: `docs/audit-2026-07-25-round3-full.md` (commit `7770ec3`). Seven P0 items, ordered by blast radius.
Line numbers are from `7770ec3`; confirm by symbol name before editing.

## Read this section before touching any code

Three audit rounds have now produced the same outcome, and the pattern is more important than any individual bug.

- Round 1 found 4 CRITICALs. The fix pass closed each one **on the exact path the report described**. Round 2 found a
  sibling path open on every single one.
- Round 2 issued a brief that said, in bold, "write the test to exercise the bypass, not the original path." The fix
  pass did that faithfully: every named test exists, and they are good tests. Round 3 still found a sibling path open
  on all five, **and two of the fixes introduced new failure modes worse than the bug they replaced**.

So the instruction "test the bypass" was necessary but not sufficient. The deeper problem is that each fix is written
against the *sentence describing the bug* rather than against the *invariant the code is supposed to hold*. Two
concrete examples from this round:

- **P0-1** was described as "deleting `settings.json.seal` disarms the revert." The fix handles a missing *seal*
  perfectly. It does not handle a missing *settings.json*, because that was not the sentence. `SettingsStore.cs:62`
  returns defaults before any seal, recovery, or durable-evidence check runs. Deleting the settings file is strictly
  easier than deleting the seal and lands on defaults with presence lock off.
- **P0-3** was described as "attacker-minted Critical severity inverts eviction." The fix added provenance. But
  provenance is computed as `evt.Source.StartsWith("MCP.")` (`EventRetentionPolicy.cs:8-9`), and the decoy-read
  Critical sets `Source` to the observed process's own filename (`App.xaml.cs`, `OnDecoyRead`). Name a credential
  harvester `MCP.exe` and Foreman's flagship tripwire alert is classified as agent noise and evicted first. The fix
  created a cleaner bypass than the one it closed.

### The method to use instead

For each item below, before writing code:

1. **Write down the invariant in one sentence**, in terms of a security property, not a code path.
   Example for P0-3: "an event Foreman itself detected must never be evicted before an event an agent reported."
2. **Enumerate every input that feeds the decision**, and for each ask: can an attacker influence this? A string
   derived from a filename, a path, a CLI argument, an absent file, or a field the caller supplies are all
   attacker-influenceable. `Source.StartsWith("MCP.")` failed exactly this test.
3. **Enumerate every way to violate the invariant**, not just the reported one. Deleting a file, renaming it,
   pre-creating it, leaving it absent, supplying an empty value, and arriving through a different verb or a different
   caller are all distinct paths. Close the **class**, not the instance.
4. **Check the fail-open direction.** For every new conditional, ask what happens when the guard data is missing.
   P0-2's root check is skipped entirely when no root is recorded, which is the default state of every machine that
   has not already completed a Guardian install.
5. **Then** write the bypass test, from step 3's enumeration, and confirm it fails on `7770ec3` before you fix it.

### Two additional rules this round

- **Do not trade one failure for another.** Two of five round-2 fixes regressed. Before shipping each item, state
  explicitly what the fix does on: first run, upgrade from an older install, a legitimate operator action, a slow or
  absent dependency, and a transient failure. If any of those got worse, the fix is not done.
- **A guard that reads its own trust signal from attacker-reachable data is not a guard.** Provenance from a process
  name, an install root from a resolved path, an opt-in from argv on the binary the attacker invokes. Each of these
  shipped this round. Trust signals must come from a boundary the attacker cannot write.

---

## P0-1 — Release payload validator has no purity check on the payload root

**Blast radius: highest.** This is the one that puts a tampered binary in a user's hands with every verification
mechanism reporting success.

**Defect.** `scripts/Test-ReleasePayload.ps1:66-93` validates four hardcoded helper directories and never checks the
payload **root** (the directory containing `Foreman.exe`) or the tree as a whole. The audit demonstrated this
empirically rather than inferring it: a real 591 MB alpha4 payload with a planted root `version.dll`, a new
`amd64\KernelTraceControl.dll` subdirectory, a hidden root file, and an extra file inside a shipped extension passes
the unmodified script with **exit 0**. It is then signed by SignPath, checksummed, and Sigstore-attested, so every
documented verification a user can perform returns success on a tampered payload. Note `version.dll` is a classic
DLL-search-order hijack target loaded from the application directory.

**Invariant.** The signed payload contains exactly the files the build produced, and nothing else, anywhere in the
tree.

**Fix.** Assert the root contains exactly `Foreman.exe` plus exactly the five known subdirectories. Recurse the whole
payload with `-Force` (hidden files included) against an allowlist, rather than checking four directory names. Have
`scripts/Copy-ReleaseExtensions.ps1` emit a manifest (it already enumerates every file) with SHA-256 per entry, verify
it at `release.yml:182` and `:227`, ship it, and verify the installed tree at app start.

**Bypass tests (must fail today).** Add four fixtures to `scripts/Test-ReleasePayloadBypasses.ps1`, each asserting a
non-zero exit: (a) root `version.dll`, (b) unknown subdirectory `amd64\x.dll`, (c) a hidden root file, (d) an extra
file inside `extensions\foreman\`. Then re-run a clean payload and assert exit 0. The suite's current two fixtures
demonstrably pass a tampered tree.

---

## P0-2 — Guardian unsigned-install anchor fails open, and the opt-in is attacker-supplied

**Defect.** Verified directly in `GuardianIntegrity.DecideForInstall` (`GuardianIntegrity.cs:66-93`):

```csharp
if (!string.IsNullOrWhiteSpace(recordedInstallRoot) && !string.Equals(resolvedRoot, ...))
    return (false, "the live launcher is outside the administrator-recorded Foreman install root.");
```

The root check is **skipped entirely when `recordedInstallRoot` is null or empty**, which is the state of every
machine that has not already completed a Guardian install. On an unsigned build (the shipping reality until SignPath
is active) the full path is: attacker stages their own canonical layout so `LayoutMatches` passes, `recordedInstallRoot`
is null so the root check is skipped, `referenceSigner` is null so signature logic is bypassed,
`allowUnsignedDevelopment` is read from argv on the binary the attacker invokes
(`Program.cs:30`, `Has("--allow-unsigned-development")`), `subjectSigner` is null, and the method returns
`(true, "explicit unsigned-development install matched the live launcher, staged layout, and recorded root.")` when
there is no recorded root at all. The round-2 chain replays with one extra CLI argument, and the success message is
misleading to anyone reading logs.

**Invariant.** An unsigned Guardian install must be authorised by something the attacker cannot write, or it must not
happen.

**Fix.** Missing recorded root must **refuse**, not skip (`GuardianIntegrity.cs:79`). Do not anchor to an
attacker-resolved root (`GuardianInstaller.cs:93`); require an out-of-band elevated step to establish it. Gate the dev
opt-in on a build-time constant excluded from Release, or a token read from an admin-only location, not argv
(`Program.cs:30`). Refuse a mode downgrade from `publisher_signed` to path+hash (`GuardianInstaller.cs:56-68`) and
reset the HKLM value in `Uninstall` (`:144-159`). Correct the success reason string so it cannot claim a root match
that did not occur.

**Bypass test (must fail today).** `DecideForInstall(recordedInstallRoot: null, allowUnsignedDevelopment: true, ...)`
must return `Trusted == false`. No such test exists: `GuardianIntegrityTests.cs:37` always passes a non-empty root, so
the fail-open branch is untested. Add a second test asserting an unsigned drop-in inside a recorded root cannot
overwrite an existing `publisher_signed` policy.

---

## P0-3 — Three ways `settings.json` is silently disarmed or destructively wiped

Three distinct paths, one invariant. Fix them together.

**Invariant.** Foreman never starts with a weaker posture than the last one the operator sealed, and never destroys
the operator's configuration without their say-so.

**(a) Deleting the file entirely is unchecked.** `SettingsStore.cs:62`:
`if (!File.Exists(path)) return new ForemanSettings();` returns defaults **before** any seal, recovery, or
durable-evidence check. All the P0-1 machinery from last round lives downstream of this early return and never runs.
Defaults mean presence lock off and decoy auditing off.
*Fix:* in the `!File.Exists` branch, consult `TryReadRecovery` and `SafeHasPriorSealEvidence()`. "We have sealed
before and the file is now gone" is `Tampered`: restore and alarm.
*Bypass test:* delete `settings.json` with `.lastgood` present; assert the presence lock survives and a High notice
fires.

**(b) A slow Guardian now quarantines the file.** When `IsGuardianInstalled()` is true but `TryCreate` returns null
(a boot race: Foreman auto-starts from HKCU Run while the service is still starting), a stored `g1:` seal is
classified `Unsealed` by `SettingsSeal.cs:125`, and the destructive path at `SettingsStore.cs:96-116` renames
`settings.json` and resets the posture to defaults. This is a **regression introduced by the P0-1 fix**: a benign
timing condition now destroys configuration.
*Fix:* when the guardian is installed but unreachable, install a sealer that returns `Unverified` for `g1:` seals.
Never classify a `g1:` seal as `Unsealed` while prior-seal evidence exists, and never re-seal a `g1:` install locally
without explicit operator action.
*Bypass test:* with a `g1:` seal, a registered event source, and `TryCreate` forced to null, assert the verdict is
`Unverified` and `settings.json` is **not** renamed.

**(c) Any future projection change wipes every upgrading user.** `SettingsSeal.cs:43-88` has no version field, and the
projection demonstrably changed between `v0.1.0-alpha2` and `alpha3`. An old seal against a new projection reads as
`Tampered`, so the next release silently wipes settings and fires a false tamper alarm on every upgrade.
*Fix:* prefix the local seal with a scheme (`l2:`) and treat an older parseable scheme as adopt-and-reseal.
*Bypass test:* seal with an N-1 projection, load with the N projection, assert settings preserved and no alarm.

---

## P0-4 — Fix the two regressions the last pass introduced

**(a) Provenance is spoofable by filename.** `EventRetentionPolicy.IsAgentReported` is
`evt.Source.StartsWith("MCP.")` (`EventRetentionPolicy.cs:8-9`), and eviction sorts
`.ThenByDescending(IsAgentReported)`, so agent-reported dies first. But `Source` is the third positional parameter of
`ForemanEvent`, and the decoy-read Critical sets it to `Path.GetFileName(d.Image)` plus the pid. A harvester named
`MCP.exe` makes Foreman's own flagship tripwire sort as agent noise and get evicted ahead of everything else.
*Fix:* add `EventOrigin { Host, Agent }` as an init property on `ForemanEvent` (`ForemanEvent.cs:15`), set it at every
publish site, and have `IsAgentReported` read only that. Provenance must be set by the publisher, never inferred from
a string an attacker can influence.
*Bypass test:* a `CommandAlertEvent` with `Source = "MCP.exe (pid 4242)"` must classify as Host and survive an agent
flood.

**(b) The supervisor bound destroys a pending UAC launch.** The controller-side 60s connect timeout added in
`ElevatedSidecarController` is correct and sufficient on its own. The supervisor-side
`maxLaunchInProgressTicks` relaunch (`SidecarSupervisor.cs:89-124`) fires at roughly 150s, which is inside the window
a human may still be looking at the UAC prompt: it destroys the pending launch, poisons `_launchFailed`, and
permanently disqualifies its own recovery, silently. One failure traded for another.
*Fix:* remove the supervisor-side relaunch and rely on the controller timeout. Give the nonce read at
`ElevatedSidecarController.cs:152` the same linked `CancelAfter` token the connect wait already has.
*Bypass test:* a supervisor test where `LaunchInProgress` stays true and the relaunch callback sets `LaunchDeclined`
must still relaunch once the prompt resolves. The current rig (`SidecarSupervisorTests.cs:22-32`) models neither
condition.

---

## P0-5 — Payment card gates are verb-scoped and arg-blind

**Context.** The card feature's core is genuinely well built: the AEAD envelope, the per-entry harness ACL, and the
unconditional `Hold(final: true)` on a card reference are correct, and no traced path lets an agent read a PAN or
security code in plaintext. Keep all of that. The problem is only the reach of the gates.

**Defect.** `CuHeuristics.Evaluate` (`CuHeuristics.cs:31-38`) performs the `HasPaymentCardReference` and signup checks
**inside the `verb == "type"` branch**, so a card reference arriving under any other verb skips them. The executor
also checks the whole submitted value rather than the specific argument it is filling
(`ForemanMcpTools.cs:1707-1709`), so a card reference embedded in `value` alongside a benign whole-value decoy in
another arg gets through. In `extension/background.js:295-299` and `:334-338`, the password policy is evaluated before
the card policy, so a mixed reference list resolves down the password path.

**Invariant.** A payment card release requires explicit operator approval regardless of which verb, argument, or
extension path carries the reference.

**Fix.** Hoist both checks to the top of `Evaluate`, outside the verb branch. Add a browser verb allowlist in
`CuBroker.SubmitAsync` mirroring `:106`/`:115` with the same `Length is > 0 and <= 40` bound. Have the executor name
the argument key it is filling and check the whole value against **that argument only**. Make the extension evaluate
the card policy first, or run both.

**Bypass tests (must fail today).** A card reference under verb `click` must Hold. A card reference embedded in
`value` with a decoy whole-value in `x` must be refused. References `[password, cardnumber]` must produce the
`__invalid__` refusal rather than filling a password field.

**While here (cheap, high value):** `SecretRedactor` has 20+ credential rules and zero card awareness
(`SecretRedactor.cs:29-60`), so a Stripe *test key* is masked in an alert body while a real PAN is not. Lift
`PassesLuhn` from `VaultView.xaml.cs:419` into Core and add a Luhn-validated PAN rule plus the card term list.

---

## P0-6 — The decoy tripwire fails silent

**Defect.** The flagship detection is permanently disarmed by an ordinary `File.Delete` of a bait file, generates no
audit record when that happens, and Setup Health then reports it green in two separate rows. The SACL at
`DecoyAudit.cs:163` audits `ReadData` only, so deletion is invisible. `Start()`'s bool is discarded at
`Foreman.EtwSidecar/Program.cs:61`, so a failed arm is never surfaced. `SetupHealth.cs:128` gates on
`SidecarConnected`, which proves the helper is running, not that any decoy is armed. `Revalidate` is documented at
`DecoyCredentials.cs:368` as running at startup and does not.

**Invariant.** If the tripwire is not armed, the operator is told; if a bait file is removed, that is itself an event.

**Fix.** Add `FileSystemRights.Delete | WriteData` to the ACE and widen the watcher query at `:83` to include event
4660. Stop discarding `Start()`'s result; report armed-versus-expected counts over the pipe and gate `SetupHealth`
on that number rather than on connectivity. Call `Revalidate` at startup as documented, and publish a High notice
when tracked coverage shrinks without a settings change.

**Bypass test (must fail today).** Delete a tracked bait file, restart, assert Setup Health reports Attention on both
the decoy row and the read-auditing row and that a High notice was published. Separately, on an armed system, delete a
bait file and assert a 4660-derived alert fires.

---

## P0-7 — Any branch can be released under a version tag

**Defect.** `release.yml` triggers on `push: tags: v*` and on `workflow_dispatch` with a free-text version, and never
checks that the tagged commit is an ancestor of `main`. A tag pushed on a side branch produces a fully signed,
checksummed, attested release.

**Fix.** Add a step that fails unless `git merge-base --is-ancestor $GITHUB_SHA origin/main` succeeds, applied to both
triggers, and require an annotated or signed tag.

**Bypass test.** Push a `v*` tag on a side branch in a fork and assert the workflow fails before the sign step.

---

## Definition of done

1. Every bypass test above exists, FAILED on `7770ec3`, and passes after.
2. For each item, the commit body states: the invariant in one sentence, and what the fix does on first run, on
   upgrade, on a legitimate operator action, and when a dependency is slow or absent. If any of those got worse, it is
   not done.
3. No new guard derives its trust signal from a filename, a resolved path, an argv flag on an attacker-invocable
   binary, or an absent file treated as permission.
4. `dotnet build Foreman.slnx -c Debug` clean; all six suites pass.
5. Anything deliberately deferred is listed explicitly rather than left implied by silence.

P1 and P2 items (profile suppression sealing, `cu_complete_action` state and modality guards,
`liveweave_poll_commands` `CanMutate`, durable log retention, presence prompt text naming the origin and the word
"card", card ACL behind a fresh tap, vault file ACLs, `ScanRepoForAgentConfig` authorization for the third audit
running, seal projection coverage) are in `docs/audit-2026-07-25-round3-full.md` section 9 and are out of scope here.
