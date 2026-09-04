# Evidence: what an antivirus does to a machine running AI coding agents

**Harvested:** 2026-09-05, from Bitdefender Total Security's own attack-chain store on a single developer
workstation, before uninstalling it. `C:\ProgramData\Bitdefender\Bitdefender Security App\ctc\rca\*.dat`, which is
plain JSON.

**Why this document exists.** Every incident below is a false positive on ordinary software development. Together
they are the argument for a registrable software class that lets an agent supervisor and a security product
deconflict, instead of the security product silently interdicting work it cannot attribute. They are also a
negative corpus for detection testing: a detector that fires on any of these commands is wrong.

**This data is destroyed by uninstalling the antivirus.** It was captured deliberately beforehand.

---

## 1. The headline

Six incidents. 497 process nodes. 292 distinct command lines. Nine of those commands were classified as malware.

**All nine were Microsoft-signed binaries.**

| Binary | Authenticode signer | Bitdefender verdict |
|---|---|---|
| `powershell.exe` | Microsoft Corporation | `ATC.Malicious` (x2) |
| `powershell.exe` | Microsoft Corporation | `CMD:Heur.BZC.ZFV.Boxter.100000.F7FED162` |
| `powershell.exe` | Microsoft Corporation | `CMD:Heur.BZC.NVN.Pantera.47.242DA45E` |
| `pwsh.exe` (bundled in the Codex runtime) | Microsoft Corporation | `Generic.PWSH.Downloader.D.031B4F0D` |
| `csc.exe` (.NET Framework) | Microsoft Corporation | `Gen:Variant.MSILHeracles.265838` |
| `csc.exe` (Roslyn, .NET SDK 10.0.400) | Microsoft Corporation | `Gen:Heur.Ransom.Imps.3` (x2) |
| `VBCSCompiler.exe` (Roslyn build server) | Microsoft Corporation | `Gen:Heur.Ransom.Imps.3` |

That table is the whole case. **A valid Authenticode signature from Microsoft did not prevent the C# compiler from
being classified as ransomware.** Signing identifies a publisher. It does not explain behaviour, and behaviour is
what was flagged. So "sign your code" is not an answer to this problem, which is the response a security vendor
reaches for first.

---

## 2. The incident that cost five days

`822979293.dat`. A 130-node attack graph, 129 transitions, depth 29, score 54.

```
attack_types                 : ["Malware", "Ransomware"]
trigger_detection_name       : Gen:Heur.Ransom.Imps.3
trigger_file_path            : ...\tests\foreman.core.tests\obj\release\net10.0\foreman.core.tests.dll
trigger_process_path         : c:\program files\dotnet\sdk\10.0.400\roslyn\bincore\vbcscompiler.exe
real_trigger_detection_name  : CMD:Heur.BZC.ZFV.Boxter.100000.F7FED162
real_trigger_cmdline         : powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ...
node[0].extra.cmd_line       : claude.exe --output-format s...
```

Read the chain from the bottom. An AI coding agent ran its ordinary PowerShell tool call. That command matched a
heuristic. Bitdefender then built an attack chain outward from it across 130 processes, and the Roslyn build server
writing a unit-test DLL at the far end of that chain was classified as ransomware and denied the write.

The developer saw none of this. What reached them was `MSB3021` and then `CS2012: Cannot open ... for writing --
Access to the path is denied`, repeated for five consecutive days, with no signal from anywhere that an antivirus
was the cause. The most-tested assembly in the project could not be built, so roughly 1,167 tests could not run,
across the settings seal, event log store, MCP auth tokens, caller scope, kill guard and vault crypto.

A second incident, `64925013.dat`, is the same verdict against `csc.exe` writing the same project's artifacts into
a temp directory, so this was not a one-off attribution accident.

Two more things Bitdefender did without surfacing anything actionable:

- **It silently reverted the monitored product's own `HKCU\...\Run` key, twice.** Auto-start simply stopped
  working. OneDrive, Edge, Chrome and other entries in the same key were untouched.
- **It classified the Codex agent's bundled PowerShell 7 as a password stealer.** `Generic.PWSH.Downloader.D`,
  malware type `Malware`, family `Agent`, on a Microsoft-signed `pwsh.exe` inside the Codex runtime cache.

---

## 3. What the agent workload actually looks like

The 292 distinct command lines, by binary:

| Binary | Distinct commands |
|---|---|
| `powershell.exe` | 55 |
| `bash.exe` | 49 |
| `git.exe` | 27 |
| `claude.exe` | 21 |
| `rustc.exe` | 13 |
| `csc.exe` | 12 |
| `dotnet.exe` | 12 |
| `cargo.exe` | 11 |
| `cvtres.exe` | 10 |
| `reg.exe` / `link.exe` | 9 each |

This is a build machine. Compilers, linkers, source control, package managers and shells, driven by an agent
instead of by a human at a keyboard. Nothing here is unusual for software development. What is unusual, from a
heuristic engine's point of view, is the *rate* and the *shape*: hundreds of short-lived processes spawned
programmatically, many of them PowerShell invoked non-interactively with an execution-policy bypass, writing
freshly compiled unsigned binaries.

That shape is genuinely close to the malicious one. The engine is not being stupid. It is missing a single piece of
context that would resolve the ambiguity completely: **which agent session caused this, and is that session under
supervision.** Nothing in Windows today lets it ask.

---

## 4. The specific pattern that poisons the chain

The three PowerShell detections all fired on the same invocation shape, which is how both Claude Code and Codex
call PowerShell:

```
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { ... } catch {}"
powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand <base64>
```

`-ExecutionPolicy Bypass`, `-NonInteractive` and `-EncodedCommand` are all reasonable heuristic inputs in
isolation. They are also exactly what a well-behaved tool harness emits, because it must not be blocked by machine
policy, must not prompt, and must pass a multi-line script through a single argument.

Eleven distinct encoded blobs appear in the corpus. All were decoded during this harvest and checked: they are
harness wrapper scripts (output-encoding setup, exit-code capture, a path to a scratch `.ps1`). **No credentials,
tokens or secrets were found in any of them.**

Worth noting for calibration: this same invocation shape is what TraceBrake's own `win-001` and `win-002` rules
fire on, producing 79 alerts an hour against its own supervising agent. Both engines are making the same mistake
for the same reason.

---

## 5. The corpus

Two files under `tests/fixtures/av-corpus/`:

- **`av-fp-command-corpus.json`** (292 unique commands). Each entry carries the command line, process path,
  Authenticode signer, integrity level, parent process, occurrence count, and whether it was flagged and with what
  verdict. This is the **negative corpus**: every entry is benign, so a detector that fires on one is producing a
  false positive. Nine entries are marked `flagged: true`, which makes them the hard cases, since a real product
  called them malware.
- **`bd-atc-false-positive-corpus.json`** (6 incidents, 497 nodes). The full attack graphs with parent/child
  relationships, depth, phase, scores, hashes and signature metadata. Useful for reasoning about how a chain gets
  built and where attribution goes wrong.

**Redaction applied and verified:** username, SIDs, shell snapshot ids, and two unrelated project names replaced
with `<USER>`, `<SID>`, `<SNAPSHOT>`, `<PROJECT-A>` and `<PROJECT-B>`. Verified zero residual matches. Paths inside
this project are deliberately left intact, since they are what makes the incidents legible.

Intended uses, in order of value:

1. **Regression corpus for TraceBrake's own command detection.** Firing on any of these is a bug. This pairs with
   the AMSI and PowerShell detection module being specced separately: that module should be measured against this
   corpus before it ships, not after.
2. **Evidence for the harness-monitor standardisation case.** A vendor conversation that opens with "your product
   classified `VBCSCompiler.exe` as ransomware and cost a developer five days" is a different conversation from one
   that opens with a proposal.
3. **A worked example of the occlusion problem.** The developer had no way to learn that an antivirus was the cause.
   That is the single exchange a negotiation protocol most needs to support.

---

## 6. What this evidence argues for

Three claims, each supported above rather than asserted.

**Code signing does not solve this.** Nine flagged binaries, all Microsoft-signed. Any proposal resting on
"sign your binaries and you will be fine" is refuted by this data.

**Exclusions are the operator's real pain, and they are unverifiable.** The operator's stated top issue was not
quarantine but getting the product to respect exceptions. Note that Microsoft's own `MpCmdRun -CheckExclusion`
reports only *that* a path is excluded, not *which* rule matched, so even on Defender an operator cannot confirm
that the exclusion they added is the one taking effect. Any negotiation protocol has to make exclusion state
queryable and verifiable, or it solves the wrong problem.

**The missing input is attribution, and only the agent supervisor has it.** The antivirus can see
`powershell.exe` spawned by `claude.exe`. It cannot see that this is tool call 412 of a supervised session, that
the session is under policy, or that the DLL at the end of the chain is a build output rather than an encrypted
victim file. The supervisor knows all three and has no way to say so.

That gap is the thing to standardise.
