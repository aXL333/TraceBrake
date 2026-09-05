# Leaving Bitdefender: Defender cutover and the TraceBrake bridge

**Date:** 2026-09-05
**Question asked:** can TraceBrake cover the gap well enough to confidently uninstall Bitdefender, targeting the
Microsoft Defender boundary rather than any single third-party vendor?

**Method:** seven research lenses, each adversarially fact-checked by a second pass, then a completeness critic that
found six blocking defects in the first draft. Every load-bearing fact below was then re-verified directly on this
machine. Facts marked VERIFIED were read live today. Anything not so marked is documentation applied to this
machine, and this box is Windows 11 Home **Insider Preview 10.0.26220**, so GA documentation is being applied to a
preview OS.

---

## 1. The finding that changes the question

The premise everyone has been working from is wrong, including mine.

Microsoft Defender is not sitting in passive mode waiting to take over. **It is completely stopped, with no engine
and no signatures at all.** VERIFIED today:

| Signal | Value |
|---|---|
| `AMRunningMode` | `Not running` |
| `AMServiceEnabled` / `AntivirusEnabled` / `RealTimeProtectionEnabled` | `False` |
| `AMEngineVersion` / `AMServiceVersion` | `0.0.0.0` |
| `AntivirusSignatureVersion` | *(blank)* |
| `IoavProtectionEnabled` / `OnAccessProtectionEnabled` / `NISEnabled` / `AntispywareEnabled` | all `False` |
| `QuickScanAge` / `FullScanAge` | `4294967295` (never-run sentinel) |
| `WinDefend` service | `Stopped`, `Manual` |
| Defender scheduled tasks | **zero** |
| AMSI providers registered | **zero** |
| `Get-MpPreference` | throws `CimException 0x800106ba` |
| `AMProductVersion` | `4.18.25110.3` (platform binaries present, service never started) |

Bitdefender owns the boot slot: `bdelam Start=0`, while `WdBoot`, `WdFilter` and `WinDefend` are all demoted to
`Start=3`. In `root\SecurityCenter2`, Windows Defender's heartbeat is frozen at **2 August 2026** while
Bitdefender's is current.

Three consequences follow, and they reframe everything.

**You are not giving up defence in depth. There is no depth.** One product protects this machine, and the question
is only which one. That makes the decision much simpler than it looked.

**Nothing on this machine has been scanning script content for over a month.** Zero AMSI providers means no
PowerShell, WMI, Office macro or .NET script content is being submitted to any scanner by anyone. Switching to
Defender closes that gap rather than opening it.

**The handover is the risky part, not the destination.** Between the uninstall and the first successful signature
update, the machine has no engine, no signatures and no real-time protection from anybody. That window is the whole
risk of this operation, and it is entirely controllable.

The good news is that the shutdown is **cooperative, not policy-locked**. `DisableAntiVirus=1` and
`DisableAntiSpyware=1` sit in the Defender **product** key, which is Defender standing itself down because another
AV holds the WSC registration. Microsoft documents that condition re-enabling automatically on uninstall.

One caveat that the first draft of this plan got wrong and the critic caught. `HKLM\SOFTWARE\Policies\Microsoft\
Windows Defender` **does exist** on this machine, and it contains a `Policy Manager` subkey (the Policy CSP
location, where `AllowAntivirus` and `AllowRealtimeMonitoring` land) that **returns access denied to a
non-elevated read**. VERIFIED. So the go/no-go gate below must be run **elevated and recursively**. A policy-level
lock could be sitting in there unread, and a non-elevated check would still say GO.

---

## 2. Verdict

**Yes, uninstall it, and the reason is false alarms, not detection rates.**

The two engines are close enough on detection that the difference should not drive this decision, and I am
deliberately not quoting the comparison figures the research produced: they were uncited, and the false-alarm half
of the claim runs against Microsoft's own historical record in that test. Do not decide on a number I cannot source.

Decide on what actually happened to you. Bitdefender's Advanced Threat Defense has, on this machine: quarantined
your own build output as `Gen:Heur.Ransom.Imps.3`, denied the C# compiler write access to
`Foreman.Core.Tests.dll` for five consecutive days, and silently reverted TraceBrake's own `HKCU` Run key twice.
Those are the injuries. The component causing them is the component you would be removing.

**What is not true is that TraceBrake needs to ship anything first.** Nothing in phases 1 through 6 is a
prerequisite. The gate is a written procedure, executed carefully, online, with a rollback point. That is Phase 0,
and it is one document and one read-only script.

**What TraceBrake adds afterwards is attribution and visibility, not antivirus coverage.** Defender is a far better
detector than TraceBrake will ever be. What Defender cannot do is tell you which Claude Code or Codex session
produced the file it just quarantined. That join is TraceBrake's actual lane, and it should be sold as nothing
more.

### One thing to expect, stated plainly

**Defender will probably flag TraceBrake too.** Switching vendors does not fix this. TraceBrake's profile is an
unsigned, zero-prevalence binary that enumerates and kills processes, subscribes to WMI process creation, reads
antivirus state, writes a Run key, hosts a bearer-auth HTTP listener on a fixed port, and supervises an elevated
sidecar. That is a textbook heuristic RAT profile, which is exactly why Bitdefender called it
`Gen:Heur.Ransom.Imps.3`. `PUAProtection=1` is already configured in the product key (VERIFIED) and goes live the
moment Defender resumes.

Plan for a Defender detection on TraceBrake in the first week rather than treating it as a shock. And do not
schedule around code signing as the fix: a fresh SignPath Foundation OV certificate carries **no** reputation
standing, and reputation accrues per certificate over months. Signing helps eventually. It will not help in week
one.

---

## 3. What you actually lose

Honest accounting. Two of these are real and nothing in this plan fully recovers them.

| Loss | Severity | Covered by |
|---|---|---|
| **The cutover window itself.** No engine, no signatures, no real-time protection between uninstall and first update. | High, transient | Procedure. Section 4 exists for this. |
| **URL and web reputation in Chrome and Firefox.** Network Protection is documented Pro/Enterprise only; this is Home (SKU 101). | Medium | External. Edge keeps SmartScreen. Chrome and Firefox fall back to Google Safe Browsing, which is real but is not Microsoft's feed. Consider DNS filtering. TraceBrake's DNS work reports novelty, never maliciousness, and must never be called web protection. |
| **Ransomware file rollback.** Bitdefender restores targeted files after blocking. Microsoft has no equivalent: Controlled Folder Access prevents writes and never restores, and Microsoft's own CFA docs point at OneDrive versioning or a separate backup. | Medium | Partly Windows, later TraceBrake. **System Protection, File History and OneDrive versioning close most of this on cutover day for zero code.** Do that in Phase 0. Phase 4's journal is the better fit later, but it is undo, not defence. |
| **Behavioural blocking depth.** ATD is a live behavioural blocker. | Low | Defender behaviour monitoring plus ASR. On the specific injuries you suffered this is arguably a gain. |
| **Safepay hardened browser.** Defender Application Guard, the nearest Microsoft equivalent, was removed in Windows 11 24H2. | Low | Nothing. Straight loss. Separate browser profile and the bank's MFA. |
| **VPN, Anti-Tracker.** Fourteen Bitdefender processes are resident right now, so their absence will be noticeable. | Negligible | External. Not malware defences. |
| **Vulnerability scanning.** Defender Vulnerability Management needs Defender for Endpoint P2. | Negligible | Phase 6, and note the research overclaimed here: `winget upgrade` sees Windows apps, not npm, NuGet or pip. If you want the ecosystem risk covered, it has to be `npm audit`, `dotnet list package --vulnerable` and `pip-audit`. |
| **Uninstall remnants.** Six Bitdefender drivers including a boot-start ELAM. A botched removal can leave a boot filter behind. | Medium | Phase 0 sweep, vendor removal tool. Never hand-delete a driver service. |

Three free Windows features are currently unconfigured and partially compensate. All are Home-SKU available and
none is in any vendor's plan: **SmartScreen for apps and files** (`SmartScreenEnabled` is absent from the registry,
VERIFIED, so its state is unknown), **Exploit Protection** (`Set-ProcessMitigation`, the EMET successor), and
**Enhanced Phishing Protection**. For a machine where an AI agent downloads and runs binaries, app reputation is
arguably the modality that matters most, and it is currently untracked.

---

## 4. Phase 0: the cutover

This is the only phase gating the uninstall. One document, one read-only script, no product code.

**To be explicit about an ordering contradiction in the research:** the runbook and the verifier script are the
handover witness. Phase 1's posture panel is a **post-cutover regression detector**, not a prerequisite. Do not wait
for it.

### 4.1 Pre-flight, all of it before you touch the uninstaller

None of this was in the first draft. Every item exists because its absence has a failure mode that ends with an
unprotected machine.

1. **Read the whole Defender policy hive, elevated and recursive.** This is the go/no-go gate and the
   non-elevated version is blind:
   ```
   reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /s
   ```
   **GO** if no `DisableAntiVirus` or `DisableAntiSpyware` value is set to 1, and `Policy Manager` contains no
   `AllowAntivirus=0` or `AllowRealtimeMonitoring=0`. **STOP** if any of those exist: removing Bitdefender would
   leave the machine with nothing and Defender would not come back on its own.
2. **Create a System Restore point, or better, a disk image.** The research identified "Defender does not come
   back" as the catastrophic branch and then shipped that question unanswered. A restore point is the answer.
3. **Stage the offline definitions next to the removal tool.** Download `mpam-fe.exe` (Microsoft Security
   Intelligence) and the Bitdefender Uninstall Tool to local disk now. VERIFIED: `wuauserv` is `Stopped/Manual` and
   `BITS` is `Stopped/Manual`, so `Update-MpSignature` may well fail, and you do not want to discover that with no
   AV running.
4. **Run a full Bitdefender scan and let it finish clean.** You are deleting the only working scanner on a machine
   where Defender has been off since 2 August. Ask it whether the box is clean before you remove it.
5. **Review and empty Bitdefender's quarantine.** Some AV uninstallers restore quarantined items. That would
   release real malware onto a machine that at that moment has no engine and no signatures.
6. **Confirm BitLocker / Device Encryption state, elevated** (`manage-bde -status`). You are about to reboot
   through a boot-start driver change. `manage-bde` denies a non-elevated read, so this has not been confirmed.
7. **Close the harnesses, TraceBrake and any build.** Kill the App PID; the sidecar self-exits.

### 4.2 Cutover

8. **Record the baseline** so you can prove what changed. Capture `AMRunningMode`, `AMServiceEnabled`,
   `AMProductVersion`, `AMServiceVersion`, `AMEngineVersion`, `AntivirusSignatureVersion`, `IsTamperProtected`,
   plus the `root\SecurityCenter2` product list with timestamps. Save it to a file.
   > `AMProductVersion` vs `AMServiceVersion` is the discriminator that matters and the research nearly missed it:
   > `4.18.25110.3` against `0.0.0.0` means the platform is installed and the service has simply never started.
9. **Uninstall Bitdefender** via Settings > Apps. If the normal uninstall reports any error at all, stop and use the
   vendor removal tool instead of pressing on.
10. **Restart the whole machine.** Not the harness, not TraceBrake. A boot-start ELAM change cannot take effect
    without it.
11. **Update signatures immediately, elevated.** This is the step that closes the exposure window, and it is the
    first thing you do after logging back in. `Update-MpSignature`, and if it fails, run the staged `mpam-fe.exe`.
    Do not browse, download or build until `AMEngineVersion` is non-zero.

### 4.3 Verify, and do not accept status bits alone

12. **Read the documented signals:** `AMRunningMode` = `Normal`; `AntivirusEnabled`, `RealTimeProtectionEnabled`,
    `AMServiceEnabled`, `BehaviorMonitorEnabled` all `True`; and also the four on-access sub-switches the first
    draft omitted, all currently `False` and all of which decide whether files are actually scanned:
    `IoavProtectionEnabled`, `OnAccessProtectionEnabled`, `NISEnabled`, `AntispywareEnabled`. `WinDefend` and
    `wscsvc` `Running`. `root\SecurityCenter2` listing Defender alone.
13. **Prove it functionally with an EICAR drop.** The plan's own invariant says never assert protection from a
    status bit, and then the first draft gated entirely on status bits. Write the EICAR test string to a scratch
    directory, never a repo, and confirm Defender takes it within seconds. Ten seconds of work, and it is the only
    step that proves anything actually scans.
14. **Check the scheduled tasks exist.** VERIFIED: this machine currently has **zero** tasks under the Windows
    Defender task path, out of 204 visible tasks. A healthy box has four (Cache Maintenance, Cleanup, Scheduled
    Scan, Verification). Without them you get one manual scan and then nothing, ever, while every status bit reads
    green.
15. **Validate cloud protection.** `MpCmdRun.exe -ValidateMapsConnection`, elevated, then read `MAPSReporting`,
    `SubmitSamplesConsent`, `DisableBlockAtFirstSeen`, `CloudBlockLevel`. VERIFIED: `SpyNetReporting=2` and
    `SubmitSamplesConsent=1` are configured, but Defender without a live MAPS connection and block-at-first-sight
    is a materially weaker product than the one the comparisons measure.
16. **Take the preference baseline, then arm Tamper Protection** (Windows Security > Virus & threat protection >
    Manage settings). That order matters: know what state you are locking before you lock it. Read the result only
    from `(Get-MpComputerStatus).IsTamperProtected`, because the registry currently says `TamperProtection=0x1`
    while the API says `False`. TraceBrake must never set this.
17. **Check whether Defender re-enrolled its AMSI provider:** `reg query "HKLM\SOFTWARE\Microsoft\AMSI\Providers"
    /s`, looking for `{2781761E-28E0-4109-99FE-B9D127C57AFE}`. Zero providers today. If it is still empty once
    Defender reads Normal, that is a finding to chase, not a pass.
18. **Sweep for remnants, report only.** `bd*` services and the six drivers (`bdelam`, `Trufos`, `atc`,
    `bdprivmon`, `bddci4`, `bduefiscan`). Never hand-delete a driver service: incorrectly removing a boot-start
    filter can render the machine unbootable. Never delete a `SecurityCenter2` instance.
19. **Turn on the free rollback substitutes now, not in Phase 4.** System Protection with a sized shadow-copy
    store, plus File History or a scheduled copy to another disk. This closes most of the Ransomware Remediation
    gap on day one for zero code, and Phase 4 is fifth in line.
20. **Rebuild and run the full suite.** The concrete proof the original injury is healed:
    `tests\Foreman.Core.Tests\bin\Release\net10.0\Foreman.Core.Tests.dll` is written, a file that has not existed
    for five days.

### 4.4 Keep this to hand from hour one

Do not defer false-positive recovery to Phase 3. The hours after cutover are exactly when Defender is most likely to
take an unsigned build artifact:

```
Get-MpThreat
Get-MpThreatDetection
"C:\Program Files\Windows Defender\MpCmdRun.exe" -Restore -Name <threat name>
```

Capture the **Threat Name and Detection ID before restoring**, so a Microsoft false-positive submission is
possible. Do not reflexively add an exclusion.

---

## 5. The TraceBrake bridge

Six phases, none of which gates the uninstall.

**Phase 1. Defender posture panel.** Make "is anything actually protecting this machine" a permanent visible fact.
The reason this blind spot lasted a month is that nobody could see Defender had been fully stopped since 2 August
while the Windows Security app still looked healthy. `DefenderHealthReader` in `src/Foreman.Monitor/Defender/`
reading `MSFT_MpComputerStatus` via `System.Management` (already referenced), rows in
`src/Foreman.Core/Health/SetupHealth.cs`, plus an AMSI provider-count probe as a **health signal only**. Build on
`MSFT_MpComputerStatus` alone: `MSFT_MpPreference` throws whenever `WinDefend` is stopped, which is precisely the
state this must be able to report on. Start with `DefenderHealthReader` rather than the settings-callbacks refactor,
which collides with Codex in `App.xaml.cs`.

**Phase 2. Defender event bridge and agent attribution.** This is the phase that earns its place. Defender writes a
rich structured log and Microsoft explicitly blesses building your own monitoring on it for non-E5 users. What it
cannot say is which agent session produced the file it quarantined. Event 1015 is the only detection event carrying
a Process ID; join it to `ProcessTreeTracker`. Parse `EventData` **positionally** against the provider manifest,
never by regex over the localized `FormatDescription`, and never by field name (Microsoft ships typos; event 1121's
fifteenth field is literally `Inhertiance Flags`). Two corrections from the critique: the event ID table belongs in
`src/Foreman.Core/patterns/defender-events.json`, not as C# literals, per the existing KillGuard constraint; and
**develop this against `CodeIntegrity/Operational` and `Security-Mitigations/KernelMode` first**, which have
thousands of live records today, because the Defender Operational channel holds fifteen records of which fourteen
are 5007 housekeeping. There is no real detection data on this machine to test against.

**Phase 3. False-positive triage lane.** When Defender takes one of your build artifacts, make recovery obvious in
seconds instead of five days. A detection card showing what was taken, which build produced it, the Threat Name and
the Detection ID, and a copyable exclusion command that TraceBrake **renders but never runs**. Gate the
build-artifact watch strictly on a correlated Defender event, or `dotnet clean`, `obj/` churn and `git clean -xdf`
will make it the first thing you mute.

**Phase 4. Source-tree snapshot journal.** The real replacement for Ransomware Remediation, and the only phase not
gated on anything. Content-addressed, append-only, triggered on agent session boundaries. Label it **undo, not
defence**: it detects nothing and prevents nothing. Two warnings. At the IO layer, read-all-then-write-all across a
source tree *is* the ransomware behavioural signature, so the designated anti-ransomware replacement is the feature
most likely to get TraceBrake detected as ransomware. And its proving test needs restating: "byte-identical to a
git checkout" will fail on line endings and untracked files; compare against a pre-session hash manifest instead.

**Phase 5. Audit-mode policy advisor.** ASR and Controlled Folder Access are available on Home and configurable
locally. A naive "enable the recommended baseline" would recreate exactly the failure you are escaping, and the
research proved it: `c1db55ab` and `01443614` both block files that merely lack reputation or prevalence, which a
freshly built unsigned `TraceBrake.exe` is by definition. **Never recommend those in Block mode.** The value
TraceBrake adds is the audit-then-promote loop: render the AuditMode command, report what would have been blocked
over a real week of agent work, and let the operator promote. Named collisions to expect in the audit:
`5beb7efe` (obfuscated scripts) against minified extension JavaScript and generated lookup tables; `c0033c00`
(system tool imposters) against `node_modules` shipping its own `node.exe`; and `56a863a9` (vulnerable signed
drivers) against your CP210x, usbipd and AR9271 driver work, which the research cleared for Block without checking.

**Phase 6. Residual-gap sensors.** Visibility, never protection. Two hard corrections from the critique. The USN
mass-modification alarm must be **alert-only, never pause and never kill**: `npm install`, `dotnet restore`, `git
checkout` and any bulk refactor are indistinguishable from what it looks for, and pausing an agent mid-task is the
exact class of interference being escaped. And the DNS novelty sensor has its baseline inverted: for a coding
agent, resolving a domain it has never touched is the *normal* case (registry CDNs, raw.githubusercontent, docs
hosts, mirror rotations), so as specified it is a flood risk rather than a low-value sensor.

---

## 6. Invariants

Non-negotiable. Several of these prevent TraceBrake from making the machine less safe as a side effect.

1. **Never register with Windows Security Center as an antivirus.** On this SKU a registered non-Microsoft AV turns
   Defender **off entirely**, which is exactly the state this machine is in now. A WSC registration would disable
   the product the whole plan depends on. The AV registration path is signature-gated and closed to unaffiliated
   third parties anyway.
2. **Never ship an ELAM driver or pursue Microsoft Virus Initiative membership.** MVI requires a commercially
   available product that detects, prevents and remediates malware plus annual lab certification. TraceBrake is not
   that. `Microsoft-Windows-Threat-Intelligence` is likewise permanently closed; write it into the plan as closed.
3. **Never register as an AMSI provider.** A provider DLL loads in-process into every PowerShell, WSH, Office, WMI
   and .NET host on the machine. An AMSI *client* is also declined for now, on two independent grounds: it returns
   `0x80070103` here because zero providers are enrolled, and submitting agent-authored PowerShell to Defender's
   script heuristics would reproduce the false-positive problem inside TraceBrake.
4. **Never write Defender configuration.** Read, explain, render the command; the operator runs it. A tool that can
   silently add AV scan exclusions is a malware primitive, and TraceBrake's own heuristics should flag exactly that.
5. **If a write path is ever built, use `Add-MpPreference` / `Remove-MpPreference` only.** `Set-MpPreference` is
   documented to **overwrite** the entire list (exclusions, ASR rule IDs, CFA folders) and would silently erase the
   operator's whole configuration on first use.
6. **Never write anything under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`,** including as a "fix" when the
   handover verifier fails. Investigate and report.
7. **Never enable Smart App Control or App Control with the Intelligent Security Graph.** Microsoft documents that
   doing so sets Defender to passive or hybrid mode on systems with a non-Microsoft AV, disabling ASR and CFA.
8. **Never turn Tamper Protection off,** and never claim it defends against WSC-registration takeover. Microsoft
   states plainly that it does not affect how non-Microsoft AV apps register.
9. **Never trust a Defender mutation's return code.** Tamper-blocked changes "might appear to succeed but are
   actually blocked". Every write is followed by a read-back, and a mismatch is reported as blocked, never retried.
10. **Read tamper state only from `Get-MpComputerStatus.IsTamperProtected`.** The registry disagrees with the API on
    this machine right now. Documented API over registry archaeology, always.
11. **Never decode the `root\SecurityCenter2` `productState` bit-field.** It is community reverse-engineering.
    Surface `displayName` and the raw integer. Do surface each entry's timestamp: a heartbeat that stops advancing
    is a real signal, and it is how Defender's month-long absence would have been caught.
12. **Never compile a roster of AV process names, service names or disable-command strings into the binary.** That
    is the AV-killer signature that got this project quarantined. Literals live in `src/Foreman.Core/patterns/*.json`.
13. **Never present an audit-mode event as a block.** Events 1122, 1124 and 1128 mean "would have blocked".
14. **Never assert protection from a status bit.** Report what was read; fail loud on an unreadable configuration
    rather than rendering a reassuring blank.
15. **Every recommended policy is first evaluated against whether it breaks AI coding agents, unsigned fresh
    builds, or this repo's own build and relaunch paths.** A rule that blocks low-reputation files is disqualified
    from Block mode regardless of its security value.
16. **Never auto-kill, auto-quarantine, auto-revert or auto-restore.** Detect, attribute, explain, offer. This
    applies hardest to the USN journal, which carries no process identity at all and can establish only temporal
    coincidence.
17. **Never add a Defender exclusion automatically or silently.** Show the narrowest command, state the hole it
    creates, keep it visible while active, give it an expiry. An empty exclusion read must never render as "no
    exclusions configured": a non-elevated read under-reports, and `HideExclusionsFromLocalAdmins` can hide them
    even from an elevated one.
18. **Alert-volume discipline is a security property.** A feature that floods gets muted, and a muted feature is
    worse than an unshipped one. Every new event source ships with coalescing and a cooldown keyed on content,
    never on event ID.

**Non-goals:** an antivirus, a WSC-registered product of any kind, an AMSI provider or client, an EDR, a Defender
configuration manager, a replacement for Network Protection, a backup product, a firewall, a vulnerability scanner,
a second opinion on Defender's verdicts, or a tool that makes the machine less safe so agents can work.

---

## 7. Open questions for you

1. ~~**`W:` or `T:`?**~~ **RESOLVED 2026-09-05: `T:\TOOLS\Foreman` is the working folder.** The migration is done.
   T: was ten commits behind and carried a partial drive-letter rewrite but no unique work; it was verified that no
   file on T: held content absent from W: before anything was overwritten, a rollback branch
   (`pre-migration-snapshot-2026-09-05`) was taken, and T: was then brought to W:'s exact history and working tree.
   W: is retained as a backup only. Every path in this runbook and in the cutover procedure refers to
   `T:\TOOLS\Foreman`, and **the Bitdefender exclusion must be re-pointed at `T:\TOOLS\Foreman` accordingly**, since
   an exclusion still naming W: will not cover the tree now being built. The first full Defender scan will hammer
   T:, which has 196 GB free.
2. **Insider Preview.** This is 10.0.26220, not GA. Every behavioural guarantee here (automatic re-enablement, ASR
   and CFA on Home, the event ID map, Tamper Protection conditions) comes from GA documentation. That is a genuine
   operator decision, not a footnote: are you comfortable betting an AV removal on a preview build?
3. **A second opinion as a human process.** TraceBrake correctly declines to build one. That is not the same as
   deciding the machine does not need one. A periodic Microsoft Safety Scanner (MSERT) run costs nothing.
4. **The three unconfigured free features:** SmartScreen for apps and files, Exploit Protection, Enhanced Phishing
   Protection. All Home-available, all currently unset or unknown. Worth an hour after cutover.

---

*Seven research lenses, each adversarially fact-checked, then a completeness critic that rejected the first draft
over six defects: a go/no-go gate that could not see the MDM policy surface, a cutover with no functional test of
protection, no pre-flight, no rollback plan, unvalidated cloud protection, and a missing scheduled-task check. All
six are folded in above. Every fact marked VERIFIED was read directly from this machine on 2026-09-05.*
