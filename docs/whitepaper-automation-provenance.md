# Harness Output Ambiguity

### The case for an automation-supervisor software class, and for a provenance declaration that grants nothing

**Blue Heeler Software** · Draft 0.1 · September 2026
Contact: xredux@protonmail.com · Repository: github.com/aXL333/Foreman

> This document is intended for publication under a permissive licence (CC0 or MIT), deliberately not GPL, so that
> a proprietary vendor's counsel can read and implement from it without escalation.

---

## Abstract

AI coding agents have made a class of software behaviour common on developer workstations that endpoint security
products cannot distinguish from attack. This is not a claim that the detectors are badly built. At the level a
detector observes, the two are not merely similar, they are frequently identical: the same interpreters, the same
invocation flags, the same process ancestry, the same rate, the same freshly compiled unsigned outputs. I call this
harness output ambiguity.

The information that resolves the ambiguity exists, but it lives in a layer no endpoint product can see. The
supervising harness knows which agent session issued a command, under what task, under what policy, and whether the
binary at the end of a build chain is an artifact or a victim. Nothing in the operating system lets it say so, and
nothing lets a security product ask.

This paper argues for a new software class, provisionally the **automation supervisor**, and for a single artifact
it publishes: an **Automation Provenance Declaration (APD)**. The design's central property is that the declaration
grants nothing. It confers no exemption, no allowlist, no suppression, and no trust. It mints confessions, not
permissions. A declaration that could grant anything would be a self-service allowlist, which is a malware
primitive, and I treat that as the disqualifying failure mode rather than a caveat.

I present measured evidence from a single developer workstation, describe what the class must and must not be, and
set out the smallest useful request to vendors: interdiction transparency. I also describe Project Powersmell, an
in-progress machine-learning component that attacks the ambiguity from the detection side, building on prior work
from Sophos and on the CCS 2019 PowerShell literature.

---

## 1. The ambiguity

An AI coding agent is a program that writes and runs other programs on a developer's behalf. Its observable output
on Windows is a stream of short-lived processes: shells, compilers, linkers, package managers, source control.

Consider the shape of a typical agent tool call:

```
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { ... } catch {}"
powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand <base64>
```

Every flag there is load-bearing for a well-behaved harness. `-NoProfile` prevents the user's profile from
corrupting captured output. `-NonInteractive` guarantees the process never blocks on a prompt no human will answer.
`-ExecutionPolicy Bypass` is required because execution policy is a machine setting the harness does not control and
must not be broken by. `-EncodedCommand` is the only reliable way to pass a multi-line script through a single
argument without quoting hazards.

Every flag there is also a reasonable heuristic input for a detector, because malware uses them for adjacent
reasons. The harness is not imitating malware. It converged on the same flags because the same constraints apply.

Now add the rest of the workload. On the machine I instrumented, a single agent session produced 292 distinct
command lines across `powershell.exe`, `bash.exe`, `git.exe`, `rustc.exe`, `csc.exe`, `dotnet.exe`, `cargo.exe`,
`link.exe` and `reg.exe`. Hundreds of short-lived processes, spawned programmatically rather than typed, at machine
speed, terminating in freshly written unsigned binaries.

That is a build machine. It is also, viewed without attribution, a reasonable description of an intrusion.

---

## 2. Measured evidence

The following comes from the attack-chain store of a major consumer endpoint security suite on one developer
workstation, harvested before the product was removed. I deliberately do not name the vendor. The argument is about
a structural gap, not a product defect, and I have no reason to believe any competitor would have behaved
differently on the same input. Reproducing this against other engines is future work I would welcome help with.

**Incident.** A 130-node process graph, 129 transitions, depth 29, was assembled and classified as
`["Malware", "Ransomware"]`. Reading the chain from its root:

1. An AI coding agent process spawned PowerShell with the flags above.
2. That command line matched a heuristic and was recorded as the chain's real trigger.
3. The engine expanded outward across 130 processes.
4. At the far end, the Roslyn compiler server writing a unit-test DLL was classified as ransomware and denied the
   write.

The developer, who is me, saw none of that. What reached me was `MSB3021` and then
`CS2012: Cannot open ... for writing -- Access to the path is denied`, repeated for five consecutive days, with no
signal from any layer of the system indicating that a security product was the cause. The affected assembly carried
roughly 1,167 tests covering the settings seal, the event log store, authentication tokens, caller scope and vault
cryptography. None of them could run for the duration.

A second incident on the same machine produced the same ransomware verdict against a different compiler writing the
same project's artifacts into a temporary directory, so this was not a single attribution accident.

Two related behaviours are worth recording because they are the same problem in different clothes:

- The product silently reverted my own application's `HKCU\...\Run` value, twice. Auto-start stopped working with no
  error surfaced anywhere. Other entries in the same key were untouched.
- It classified a second AI agent's bundled PowerShell 7 interpreter as a password stealer.

**The result that matters most.** Across the corpus, nine distinct commands were classified as malware. All nine
were Microsoft-signed binaries: the Windows PowerShell host, the bundled PowerShell 7 host, the .NET Framework C#
compiler, the Roslyn C# compiler, and the Roslyn compiler server.

I want to state the consequence plainly, because it disposes of the first answer this problem usually receives.
**A valid Authenticode signature from Microsoft did not prevent the C# compiler from being classified as
ransomware.** Signing establishes who published a binary. It does not explain what that binary is doing, and
behaviour is what was flagged.

---

## 3. Why the existing signals do not resolve the ambiguity

**Code signing.** Refuted above by measurement. Publisher identity is orthogonal to behavioural verdicts. It is also
worth noting that an open-source project signing through a foundation programme shares a certificate subject with
every other project in that programme, so the subject identifies the programme, not the product.

**Reputation and prevalence.** A binary compiled thirty seconds ago has zero prevalence by construction. Rules that
block low-reputation or low-prevalence executables are therefore guaranteed to fire on the output of every build on
every developer machine. This is not a tuning problem, it is a definitional one.

**Exclusions.** This is the operator-facing failure, and in my experience it is the worst of them. Three compounding
problems:

- *Availability.* Behavioural engines commonly scope their exception lists to executable files rather than folders,
  on the reasonable ground that they monitor running processes. An operator who wants to exclude a source tree from
  a behavioural verdict frequently cannot express that at all.
- *Verifiability.* Even where an exclusion can be expressed, the operator generally cannot confirm it took effect.
  Microsoft's own `MpCmdRun.exe -CheckExclusion` reports *that* a path is excluded, not *which* rule matched, so a
  pre-existing parent-folder exclusion returns a pass for a rule that never landed.
- *Override.* Multiple enforcement layers exist inside one product: on-access scanning, behavioural analysis,
  machine-learning classifiers, and rollback. An exclusion honoured by one layer may be overridden by another, and
  the operator receives no machine-readable notice that this happened.

**Detecting the command text itself.** The research literature here is strong and it sharpens the point rather than
solving it. Li, Chen, Xiong, Chen, Zhu and Yang [1] built the first semantic-aware PowerShell attack detection
system, precisely because static approaches are inherently vulnerable to obfuscation, and identified 31 semantic
signatures via objective-oriented association mining. Their adversary obfuscates *form* while preserving malicious
*semantics*.

Agent harness output inverts that. It presents adversarial **form**, encoded commands and policy bypass and machine
speed, with entirely benign **semantics**. A detector tuned for the paper's threat model sees the form and has no
semantic content to contradict it, because building software genuinely does read many files, write many binaries,
and spawn many interpreters. The distinguishing evidence is not in the script. It is in the supervision context, one
layer up.

---

## 4. Why this becomes urgent rather than remaining niche

Today this problem is concentrated on the machines of developers using AI coding agents. That population is growing
quickly, and it is the population least able to tolerate the failure mode, because a silently blocked compiler write
presents as an incomprehensible build error rather than as a security event.

The support economics point the same way. Every one of these incidents is a false positive that consumes vendor
support time, erodes trust in the product, and pushes developers toward the worst available remedy: broad,
permanent, hand-written exclusions over entire source trees, or disabling protection outright. A mechanism that
reduces that pressure is in the vendor's interest before it is in mine.

---

## 5. The proposed class

**An automation supervisor** is software that observes and constrains autonomous or semi-autonomous agents executing
with a human user's credentials, and that can attribute an observed process, command or file write to a specific
supervised session.

It is defined as much by its refusals as by its function. An automation supervisor:

- is **not** an antivirus, and never registers as one;
- **never** registers with Windows Security Center, under any category. On Windows 10 and 11 client, a non-Microsoft
  antivirus registering with WSC causes Microsoft Defender Antivirus to enter *Disabled mode* automatically. A
  supervisor that registered would therefore turn off the machine's actual protection as a side effect. This is the
  single hardest constraint in the design;
- ships **no** ELAM driver, **no** minifilter, and pursues **no** antimalware-vendor programme membership;
- registers **no** AMSI provider. A provider DLL loads in-process into every scripting host on the machine, and use
  of that extension point is itself a published attacker technique;
- **enforces nothing.** The closest existing analogy is Linux `fanotify`, where the permission-capable classes
  require `CAP_SYS_ADMIN` and the non-blocking observer class is the unprivileged default. The correct summary of
  this proposal is: *we are asking for the notify class, not the content class.*

### 5.1 The artifact: an Automation Provenance Declaration

A supervisor publishes one signed, machine-readable document describing:

**Identity.** A reverse-DNS declarant identifier, product name, version, and per-file SHA-256 hashes of the
components the declaration covers. Identity binds to a signing key and to file hashes, never to a display name or a
file path.

**Declared behaviours.** The honest list of things this software does that resemble malware, drawn from a closed,
versioned vocabulary of `area.verb` tokens. For my own product that list includes process enumeration and
termination, WMI process-creation subscription, reading antivirus state, writing a run-at-login value, hosting a
loopback listener, and supervising a privileged helper. Three rules make this section safe rather than useful to an
attacker: an unknown token invalidates the whole declaration rather than degrading gracefully, so novel tokens
cannot become a laundering channel; *under*-declaration also invalidates, so minimising is worse than
over-declaring; and no entry may name a port, an authentication scheme, a service name or a registry path, because
publishing operational detail helps an attacker far more than it helps a vendor.

**Supervised subjects.** Which agent harnesses this supervisor claims to supervise, and how a process is bound to a
session. This is the field that would have resolved the incident in section 2.

**Working set.** Where normal operation produces high write churn or short-lived intermediate binaries. This section
is **purely descriptive and has no verbs.** There is deliberately no `action`, `exclude`, `allow` or `trust` field
anywhere in the schema, so a declarant *cannot express a request even if it wants to*. A future implementer who
writes `if path in working_set: skip` has converted the format into a universal exclusion API, and the specification
must mark that non-conforming in normative language.

### 5.2 Carrier: profile an existing standard rather than invent a namespace

I do not propose a new registry namespace or a new well-known file location. ISO/IEC 19770-2:2015 SWID tags, and the
IETF SACM Concise SWID work, already provide a standardised software identification tag installed alongside software
with a defined lifecycle tied to install and uninstall. An agent-attribution *profile* of an existing ISO standard is
a far easier thing to campaign for than a novel invention, and it inherits tooling, vocabulary and institutional
familiarity. This should be evaluated before any bytes of new schema are written.

Where a discovery key is nonetheless needed, it belongs in a vendor-owned hive path, written by an installer, with
an ACL set explicitly at creation rather than inherited. Two hard-won details: a machine-scope declaration must be
gated on a valid Authenticode signature verified at *read* time against the file on disk, never on a `signed: true`
field inside the document; and uninstall must delete the registration *before* the files, so that an interrupted
uninstall leaves files without a registration rather than a dangling pointer to a path an attacker can then create.

---

## 6. Normative safety properties

These are not recommendations. A design that violates any of them makes the world worse and should be rejected,
including by me.

1. **The declaration grants nothing.** No consumer may map a declaration to a scan, alert, or block decision. The
   record is one-way, from supervisor to security product.
2. **The word "negotiation" does not appear in the design.** It invites a later contributor to implement a "small"
   suppression path. The relationship is declaration, not negotiation.
3. **A declaration may never reduce a detection score**, and may never suppress a credential-access or persistence
   detection at any confidence level.
4. **Unsigned or hash-mismatched declarations are treated as absent**, never as weakly trusted.
5. **A per-user declaration is normatively defined as an assertion by whatever code runs as that user, including
   malware.** It is trivially forgeable and the defence is definitional, not technical. Say so in the specification
   rather than pretending otherwise.
6. **No personally identifying information, no watch lists, no monitored-process inventories, no thresholds and no
   detection logic** appear in a declaration.
7. **Absence of security alerts is never rendered as safety.** A supervisor must report posture as observed-and-
   unknown, with a distinct state for "this product exposes no signal here." A green tick sourced from a spoofable
   view is a laundering surface.
8. **A supervisor never writes another vendor's configuration**, and never programmatically adds, modifies or
   removes an exclusion in any product. A tool that can silently add scan exclusions is a malware primitive.
9. **A supervisor never fights an interdiction.** On detecting that its own run-at-login value was reverted, it
   re-asserts at most once, then stops and tells the operator. Looping self-reassertion is indistinguishable from
   persistence behaviour and deserves to be flagged.

I want to name the unresolved tension rather than mitigate it away. The declaration's only value is that something
eventually consumes it, and any consumption is a step toward a self-service allowlist. My answer is that consumption
must be limited to *explanation* rather than *decision*: a vendor may use a declaration to tell a support engineer
or a user why a chain looks the way it does, and may not use it as an input to a verdict. If that line cannot hold,
the format should not exist.

---

## 7. The smallest useful ask: interdiction transparency

I am not asking any vendor to trust a declaration. The first and most valuable request is much smaller, and it flows
in the opposite direction.

**When any enforcement layer interdicts an operation, emit a machine-readable record naming the path, the layer, and
the reason. When a layer overrides an operator-authored exclusion, say so.**

That is the missing signal that cost me five days. It reduces no detection capability, grants no third party any
influence over a verdict, and is a support-cost reduction for the vendor.

Windows already has vendor-neutral vocabulary for part of this. `ERROR_VIRUS_INFECTED` (225) and
`ERROR_VIRUS_DELETED` (226) are documented system error codes returned when a security product's filter blocks or
removes a file, regardless of vendor. Surfacing these consistently, rather than collapsing them into a generic
access-denied, would by itself have converted my five silent days into a five-second diagnosis.

Two design requirements if a query interface is ever built, because "did you block this?" is otherwise a direct
evasion oracle. First, `unknown` must be a distinct answer from `not-blocked`, where `not-blocked` is a positive
assertion backed by retained records covering the whole window. Second, queries must be scoped to paths the caller
can prove it owns, and rate-limited with exponential backoff.

### Prior art that makes this reasonable to ask for

- **Dev Drive.** Microsoft has already accepted that developer workloads warrant a declared trust designation with
  consequences for filter attachment, through `fsutil devdrv trust` and the antivirus filter altitude range. The
  principle is conceded. What is missing is that the mechanism is volume-scoped, format-time only, unavailable on the
  system drive, and its performance mode applies to Microsoft Defender only.
- **App Control origin claims.** Windows already records a kernel-managed extended attribute describing what wrote a
  file. Provenance as a first-class file property is not a novel idea in this operating system.
- **`fanotify`.** Linux ships kernel-arbitrated ordering across simultaneous agents with a clean split between
  permission-capable and notify-only classes. That split is exactly the one being requested here.

---

## 8. What gets built regardless of adoption

Every user-visible benefit must be reachable with zero cooperation from anyone. If the standardisation effort never
succeeds, and I assume it will not for years, the following still ships and still solves most of my problem.

**Interdiction correlation.** Watch the documented signals a security product already emits, join them to the agent
session that produced the file, and tell the developer plainly that this looks like security-product interference
rather than a compiler bug. Recognise the signature failure shapes: an access-denied on a compiler's own output, a
build artifact that vanished after being written, a run-at-login value that reverted without the product writing it.

**Attribution.** Bind every process, command and file write to a supervised agent session, so that when something
does go wrong the question "which agent did this, under what task" has an answer.

**Local declaration drift.** Compare the product's own observed behaviour against its own published declaration and
surface the difference to the operator. Behaviour beyond the declaration is a signal. An over-broad declaration is
itself worth flagging. This needs no vendor and is testable today.

---

## 9. Project Powersmell

The correlation work above tells a developer *that* something was interdicted. It does not reduce the ambiguity that
caused the interdiction. Project Powersmell is the attempt to attack that directly, and it is in development now as
a drop-in module.

**The problem restated as a learning problem.** Given a command line, a script body, and its process ancestry,
decide whether it is the output of a supervised automation session or unattributed execution. Note that this is a
different target from malicious-versus-benign, and I think that difference is the point. The existing literature
tries to separate malicious from benign script content and, per section 3, agent output sits awkwardly on that
boundary by construction. Separating *supervised* from *unattributed* is a question the harness context can actually
answer, which makes it learnable and makes the labels cheap to generate.

**Building on YaraML.** Joshua Saxe and SophosAI published YaraML [2], an open-source toolkit that trains a
classifier on labelled malicious and benign artifacts and then *compiles the trained model into human-readable YARA
rules*, using logistic regression or random forest over substring features with feature selection to control
overfitting. Sophos are explicit that it is experimental and that no ruleset is perfectly accurate.

I want to adapt that approach rather than reinvent it, for one reason above all: **the output is inspectable and
portable.** A vendor cannot deploy my neural network, and should not want to. A vendor can read a YARA rule, argue
with it, modify it, and ship it. For a proposal whose entire premise is that a third party must be able to verify
what I am claiming, an explainable rule artifact is worth more than a more accurate opaque model.

Intended adaptations, all of them open questions rather than results:

- Retarget the label from malicious-versus-benign to supervised-versus-unattributed.
- Extend features beyond substrings to include process-ancestry shape, invocation-flag combinations, inter-process
  timing, and the decoded content of encoded commands. The encoded-command layer matters: in my corpus, eleven
  distinct encoded blobs all decoded to harness wrapper scripts, and any feature extraction that stops at the base64
  is looking at the wrong thing. This is where the deobfuscation approach of Li et al. [1] is directly applicable,
  and where I expect adapting their semantic-signature method to be more productive than substring features alone.
- Evaluate honestly against a negative corpus, reporting false-positive rate on known-benign agent output as the
  primary metric rather than as a footnote.

**Corpus.** The 292 distinct command lines described in section 2 are published as a negative corpus alongside this
paper, with usernames, security identifiers and unrelated project names redacted. Every entry is benign, so a
detector that fires on one is producing a false positive. Nine entries are marked as flagged, which makes them the
hard cases, because a shipping product classified them as malware. I would like other people to add to it. A single
machine is an anecdote, and I would rather build the dataset that settles the question than keep arguing from n=1.

---

## 10. Open questions and non-goals

**The class name is unresolved.** "Harness monitor" was my working term and it cannot be used publicly: HARNESS is a
registered trademark whose guidelines explicitly forbid variations and phonetic equivalents for similar or
compatible products. Adjacent candidates fail other tests. "Agentic monitoring" collides with existing commercial
naming. "Activity monitor" is worse than useless, because activity-monitoring software is a category security
vendors deliberately classify as potentially unwanted, which would place an unsigned process-watching tray
application inside a detection category rather than outside one. I use "automation supervisor" provisionally and
would welcome a better proposal. A class name should never carry trust, because a label that connotes legitimacy is
an asset to impersonate.

**Non-goals.** This class is not an antivirus, not an EDR, not a Security Center participant, not an AMSI provider,
not a configuration manager for anyone else's product, not a second opinion on anyone else's verdicts, and not a
mechanism for making a machine less safe so that agents can work. Any exclusion an operator adds is a hole; the job
is to make that hole visible, narrow and temporary, not to open it.

**Honest odds.** I am one developer. The realistic path is to ship the implementation, publish the convention with a
small permissively-licensed reader library so an adopter's cost is an import rather than a parser, gather incident
evidence from more than one machine, and only then approach vendors with data instead of a proposal. Formal
standardisation, if it ever happens, is ratification of something already working, not the first step.

---

## References

[1] Z. Li, Q. A. Chen, C. Xiong, Y. Chen, T. Zhu, H. Yang. *Effective and Light-Weight Deobfuscation and
Semantic-Aware Attack Detection for PowerShell Scripts.* Proceedings of the 2019 ACM SIGSAC Conference on Computer
and Communications Security (CCS '19). https://doi.org/10.1145/3319535.3363187 ·
https://users.cs.northwestern.edu/~ychen/Papers/CCS19.pdf · Code: https://github.com/li-zhenyuan/PowerShellDeobfuscation

[2] J. Saxe, SophosAI. *An open source ML toolkit for automatically generating YARA rules.* Sophos.
https://www.sophos.com/en-us/blog/an-open-source-ml-toolkit-for-automatically-generating-yara-rules ·
Code: https://github.com/sophos/yaraml_rules

[3] Microsoft. *Microsoft Defender Antivirus compatibility with other security products.*
https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility

[4] Microsoft. *Dev Drive.* https://learn.microsoft.com/en-us/windows/dev-drive/

[5] ISO/IEC 19770-2:2015, *Information technology — IT asset management — Part 2: Software identification tag*, and
IETF SACM, *Concise Software Identification Tags* (draft-ietf-sacm-coswid).

[6] Corpus accompanying this paper: `tests/fixtures/av-corpus/` in github.com/aXL333/Foreman.
