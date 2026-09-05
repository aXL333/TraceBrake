# Automation Provenance

### In-session attribution for coding agents on developer machines, the workload container-scoped identity cannot reach

**Blue Heeler Software** · Draft 0.2 · September 2026
Contact: xredux@protonmail.com · Repository: github.com/aXL333/TraceBrake

> Intended for publication under a permissive licence (CC0 or MIT), deliberately not GPL, so that a proprietary
> vendor's counsel can read and implement from it without escalation.

---

## Abstract

AI coding agents have made a class of software behaviour common on developer workstations that endpoint security
products cannot distinguish from attack. This is not a claim that the detectors are badly built. At the level a
detector observes, the two are frequently identical: the same interpreters, the same invocation flags, the same
process ancestry, the same rate, the same freshly compiled unsigned outputs. I call this harness output ambiguity.

The information that resolves the ambiguity exists, but it lives one layer up. The supervising software knows which
agent session issued a command, under what task, and whether the binary at the end of a build chain is an artifact
or a victim.

Microsoft has now conceded this principle and shipped vocabulary for it. Entra Agent ID reached general
availability in April 2026, and the Microsoft Execution Containers (MXC) SDK entered early preview with an explicit
commitment that Windows "attributes all activity from the container to that identity, so you can clearly
differentiate human from agent" [3]. That is the right idea. It is also **container-scoped**, and the coding agents
that produced the incidents in this paper run in the developer's own interactive session, because they need the
real repository, the real toolchain and the real build.

This paper proposes **automation provenance**: a software class that publishes a signed **Automation Declaration**
attributing machine-generated processes, command lines and file writes to a supervised session. The declaration
grants nothing. No exemption, no allowlist, no suppression, no trust. There is deliberately no `action`, `allow`,
`exempt` or `trust` field in the schema, so a declarant cannot express a request even if it wants to. It mints
confessions, not permissions.

The register is chosen on purpose. SLSA gave the industry provenance for what was **built**. C2PA gave it provenance
for what was **published**. Nothing covers what a machine **did** on a developer's own machine.

I present measured evidence from a single workstation, set out what the class must and must not be, and make the
smallest useful request of security vendors: interdiction transparency. I also describe Project Powersmell, an
in-progress machine-learning component building on work from Sophos [2] and the CCS 2019 PowerShell literature [1].

---

## 1. The ambiguity

An AI coding agent is a program that writes and runs other programs on a developer's behalf. Its observable output
on Windows is a stream of short-lived processes: shells, compilers, linkers, package managers, source control.

The shape of a typical agent tool call:

```
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "try { ... } catch {}"
powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand <base64>
```

Every flag is load-bearing. `-NoProfile` stops the user's profile corrupting captured output. `-NonInteractive`
guarantees the process never blocks on a prompt no human will answer. `-ExecutionPolicy Bypass` is required because
execution policy is a machine setting the harness does not control and must not be broken by. `-EncodedCommand` is
the only reliable way to pass a multi-line script through one argument without quoting hazards.

Every flag is also a reasonable heuristic input for a detector, because malware uses them for adjacent reasons. The
harness is not imitating malware. It converged on the same flags because the same constraints apply.

Add the rest of the workload. On the machine I instrumented, one agent session produced 292 distinct command lines
across `powershell.exe`, `bash.exe`, `git.exe`, `rustc.exe`, `csc.exe`, `dotnet.exe`, `cargo.exe`, `link.exe` and
`reg.exe`. Hundreds of short-lived processes, spawned programmatically rather than typed, at machine speed,
terminating in freshly written unsigned binaries.

That is a build machine. It is also, viewed without attribution, a reasonable description of an intrusion.

---

## 2. Measured evidence

The following comes from the attack-chain store of a major consumer endpoint security suite, harvested before the
product was removed. I deliberately do not name the vendor. The argument is about a structural gap, not a product
defect, and I have no reason to believe a competitor would behave differently on the same input. Reproducing this
against other engines is work I would welcome help with.

**Incident.** A 130-node process graph, 129 transitions, depth 29, classified `["Malware", "Ransomware"]`. Reading
the chain from its root:

1. An AI coding agent process spawned PowerShell with the flags above.
2. That command line matched a heuristic and was recorded as the chain's real trigger.
3. The engine expanded outward across 130 processes.
4. At the far end, the Roslyn compiler server writing a unit-test DLL was classified as ransomware and denied the
   write.

The developer, who is me, saw none of that. What reached me was `MSB3021` and then
`CS2012: Cannot open ... for writing -- Access to the path is denied`, repeated for five consecutive days, with no
signal from any layer of the system that a security product was the cause. The affected assembly carried roughly
1,167 tests covering the settings seal, event log store, authentication tokens, caller scope and vault cryptography.
None ran for the duration.

A second incident produced the same ransomware verdict against a different compiler writing the same project's
artifacts to a temporary directory, so this was not a single attribution accident.

Two related behaviours, the same problem in different clothes:

- The product silently reverted my application's `HKCU\...\Run` value, twice. Auto-start stopped working with no
  error surfaced anywhere. Other entries in the same key were untouched.
- It classified a second AI agent's bundled PowerShell 7 interpreter as a password stealer.

**The result that matters most.** Nine distinct commands across the corpus were classified as malware. All nine were
Microsoft-signed binaries: the Windows PowerShell host, the bundled PowerShell 7 host, the .NET Framework C#
compiler, the Roslyn C# compiler, and the Roslyn compiler server.

The consequence disposes of the answer this problem usually receives first. **A valid Authenticode signature from
Microsoft did not prevent the C# compiler from being classified as ransomware.** Signing establishes who published
a binary. It does not explain what that binary is doing, and behaviour is what was flagged.

---

## 3. Why the existing signals do not resolve it

**Code signing.** Refuted above by measurement. Publisher identity is orthogonal to behavioural verdicts. An
open-source project signing through a foundation programme also shares a certificate subject with every other
project in that programme, so the subject identifies the programme, not the product.

**Reputation and prevalence.** A binary compiled thirty seconds ago has zero prevalence by construction. Rules that
block low-reputation or low-prevalence executables will therefore fire on the output of every build on every
developer machine. That is definitional, not a tuning problem.

**Exclusions.** The operator-facing failure, and the worst of them. Three compounding problems:

- *Availability.* Behavioural engines commonly scope exception lists to executable files rather than folders, on the
  reasonable ground that they monitor running processes. An operator who wants to exclude a source tree from a
  behavioural verdict frequently cannot express that at all.
- *Verifiability.* Where an exclusion can be expressed, the operator generally cannot confirm it took effect.
  Microsoft's own `MpCmdRun.exe -CheckExclusion` reports *that* a path is excluded, not *which* rule matched, so a
  pre-existing parent-folder exclusion returns a pass for a rule that never landed.
- *Override.* Several enforcement layers exist inside one product: on-access scanning, behavioural analysis,
  machine-learning classifiers, rollback. An exclusion honoured by one layer may be overridden by another, with no
  machine-readable notice.

**Detecting the command text.** The literature here is strong and sharpens the point rather than solving it. Li,
Chen, Xiong, Chen, Zhu and Yang [1] built the first semantic-aware PowerShell attack detection system precisely
because static approaches are inherently vulnerable to obfuscation, identifying 31 semantic signatures through
objective-oriented association mining. Their adversary obfuscates *form* while preserving malicious *semantics*.

Agent harness output inverts that. It presents adversarial **form**, encoded commands and policy bypass and machine
speed, with entirely benign **semantics**. A detector tuned for that threat model sees the form and has no semantic
content to contradict it, because building software genuinely does read many files, write many binaries and spawn
many interpreters. The distinguishing evidence is not in the script. It is in the supervision context.

---

## 4. What the platform has already solved, and what it has not

This section exists because it changes the proposal. Microsoft has moved, and this paper is deliberately positioned
as a complement to that work rather than a rival to it.

**Entra Agent ID** reached general availability in April 2026, establishing agent identities as first-class
non-human principals with enforced human sponsorship and lifecycle governance [4]. **Agent 365** discovers and
manages local agents on Windows, naming widely used coding agents explicitly [5]. And the **Microsoft Execution
Containers (MXC) SDK**, in early preview, provides process and session isolation for agents on Windows and WSL, with
the commitment quoted in the abstract: Windows assigns a local or Entra-backed identity and attributes all activity
from the container to it [3].

**The principle is therefore conceded**, and that is the hardest part of any argument of this kind. Agent activity
needs a distinct identity, and that identity should be attributable. Nothing below disputes it. The vocabulary is
also now established, and this paper adopts it rather than competing with it.

Two gaps remain, and they are what automation provenance names.

**The attribution is container-scoped.** The commitment is precise: activity *from the container*. Coding agents run
in the developer's own interactive session, because they need the real repository, the real toolchain and the real
build. MXC session isolation's initial release supports non-interactive sessions [3]. The workload that produced the
incident in section 2 sits outside the boundary, and it is the workload most developers actually run.

**None of it reaches the endpoint security product.** Even a perfectly attributed contained agent does not change
what a behavioural engine observes. It still sees a compiler writing a DLL. The operating system knowing which agent
caused it does not put that fact into a third-party verdict, and no mechanism exists to carry it across.

This paper does not propose containers, does not reimplement isolation, and does not compete with MXC. It addresses
the in-session case and the cross-product handoff.

---

## 5. The class

**Automation provenance** is the property of being able to attribute a machine-generated process, command line or
file write to a specific supervised automation session. Software that provides it publishes an **Automation
Declaration**.

Note the grammar, which is deliberate. Like Microsoft's own security feature names (controlled folder access,
tamper protection, attack surface reduction), the term is a mass noun. A machine *has automation provenance
enabled*; a product *provides automation provenance*. There is **no abbreviation**, and none should ever be
sanctioned: not in the schema, not in the file extension, not in the spec title, not in slide furniture.

The class is defined as much by its refusals as by its function. Software providing automation provenance:

- is **not** an antivirus, and never registers as one;
- **never** registers with Windows Security Center, under any category. On Windows 10 and 11 client, a non-Microsoft
  antivirus registering with WSC causes Microsoft Defender Antivirus to enter *Disabled mode* automatically [6]. A
  registration would therefore turn off the machine's actual protection as a side effect. This is the hardest
  constraint in the design;
- ships **no** ELAM driver, **no** minifilter, and pursues **no** antimalware-vendor programme membership;
- registers **no** AMSI provider. A provider DLL loads in-process into every scripting host on the machine, and use
  of that extension point is itself a published attacker technique;
- **enforces nothing.** The closest existing analogy is Linux `fanotify`, where the permission-capable classes
  require `CAP_SYS_ADMIN` and the non-blocking observer class is the unprivileged default. The correct summary is:
  *we are asking for the notify class, not the content class.*

### 5.1 The Automation Declaration

A signed, machine-readable document, `automation-declaration.json`, describing:

**Identity.** A reverse-DNS declarant identifier, product name, version, and per-file SHA-256 hashes of the
components covered. Identity binds to a signing key and to file hashes, never to a display name or a file path.

**Declared behaviours.** The honest list of things this software does that resemble malware, from a closed,
versioned vocabulary of `area.verb` tokens. For my own product that includes process enumeration and termination,
WMI process-creation subscription, reading antivirus state, writing a run-at-login value, hosting a loopback
listener, and supervising a privileged helper. Three rules keep this safe rather than useful to an attacker: an
unknown token invalidates the whole declaration rather than degrading gracefully, so novel tokens cannot become a
laundering channel; *under*-declaration also invalidates, so minimising is worse than over-declaring; and no entry
may name a port, an authentication scheme, a service name or a registry path, because operational detail helps an
attacker far more than a vendor.

**Supervised subjects.** Which agent harnesses this software supervises, and how a process is bound to a session.
Where Entra Agent ID identities exist, bind to them rather than inventing a parallel identifier. This is the field
that would have resolved the incident in section 2.

**Working set.** Where normal operation produces high write churn or short-lived intermediate binaries. Purely
descriptive, **with no verbs**. There is deliberately no `action`, `exclude`, `allow` or `trust` field anywhere in
the schema, so a declarant *cannot express a request even if it wants to*. An implementer who writes
`if path in working_set: skip` has converted the format into a universal exclusion API, and the specification marks
that non-conforming in normative language.

The word *declaration* is chosen for its customs sense. You state what is in the crate; the officer remains free to
open it. That metaphor needs no explanation, and it conveys "grants nothing" without using a word the safety
constraints forbid. It also carries a liability posture worth adopting deliberately: a declarant is answerable for a
false declaration, which is a stronger story than mere assertion.

### 5.2 Carrier: profile an existing standard

I do not propose a new registry namespace or a new well-known file location. ISO/IEC 19770-2:2015 SWID tags, and
the IETF SACM Concise SWID work, already define a standardised software identification tag installed alongside
software with a lifecycle tied to install and uninstall [7]. An automation-provenance *profile* of an existing ISO
standard is far easier to campaign for than a novel invention and inherits tooling and institutional familiarity.
This should be evaluated before any new schema bytes are written.

Where a discovery key is needed, it belongs in a vendor-owned hive path, written by an installer, with an ACL set
explicitly at creation rather than inherited. Two details learned the hard way: a machine-scope declaration must be
gated on a valid Authenticode signature verified at *read* time against the file on disk, never on a `signed: true`
field inside the document; and uninstall must delete the registration *before* the files, so an interrupted
uninstall leaves files without a registration rather than a dangling pointer to a path an attacker can create.

---

## 6. Normative safety properties

Not recommendations. A design violating any of these makes the world worse and should be rejected, including by me.

1. **The declaration grants nothing.** No consumer may map a declaration to a scan, alert or block decision. The
   record is one-way, from declarant to security product.
2. **The word "negotiation" does not appear in the design.** It invites a later contributor to implement a "small"
   suppression path. The relationship is declaration, not negotiation.
3. **A declaration may never reduce a detection score**, and may never suppress a credential-access or persistence
   detection at any confidence level.
4. **Unsigned or hash-mismatched declarations are treated as absent**, never as weakly trusted.
5. **A per-user declaration is normatively an assertion by whatever code runs as that user, including malware.** It
   is trivially forgeable and the defence is definitional, not technical. Say so rather than pretending otherwise.
6. **No personally identifying information, no watch lists, no monitored-process inventories, no thresholds, no
   detection logic.**
7. **Absence of security alerts is never rendered as safety.** Report posture as observed-and-unknown, with a
   distinct state for "this product exposes no signal here." A green tick sourced from a spoofable view is a
   laundering surface.
8. **Never write another vendor's configuration**, and never programmatically add, modify or remove an exclusion in
   any product. A tool that can silently add scan exclusions is a malware primitive.
9. **Never fight an interdiction.** On detecting that its own run-at-login value was reverted, the software
   re-asserts at most once, then stops and tells the operator. Looping self-reassertion is indistinguishable from
   persistence behaviour and deserves to be flagged.
10. **The schema may never grow an `action`, `allow`, `exempt`, `trust` or `suppress` field.** This belongs in the
    conformance section of the specification, not in design convention. The entire safety argument rests on it. See
    [the Automation Declaration format, section 5.3](spec/automation-declaration-v1.md), where this is normative and
    permanent: a version of the specification introducing any of those fields is defined as not a successor to it.

The unresolved tension, stated rather than mitigated away: the declaration's only value is that something eventually
consumes it, and any consumption is a step toward a self-service allowlist. My answer is that consumption must be
limited to *explanation* rather than *decision*. A vendor may use a declaration to tell a support engineer or a user
why a chain looks the way it does, and may not use it as an input to a verdict. If that line cannot hold, the format
should not exist.

---

## 7. The smallest useful ask: interdiction transparency

I am not asking any vendor to trust a declaration. The first and most valuable request is smaller, and flows the
other way.

**When an enforcement layer interdicts an operation, emit a machine-readable record naming the path, the layer and
the reason. When a layer overrides an operator-authored exclusion, say so.**

That is the missing signal that cost me five days. It reduces no detection capability, grants no third party
influence over a verdict, and is a support-cost reduction for the vendor.

Windows already has vendor-neutral vocabulary for part of it. `ERROR_VIRUS_INFECTED` (225) and
`ERROR_VIRUS_DELETED` (226) are documented system error codes returned when a security product's filter blocks or
removes a file, regardless of vendor. Surfacing these consistently, rather than collapsing them into a generic
access-denied, would by itself have converted five silent days into a five-second diagnosis.

If a query interface is ever built, two requirements, because "did you block this?" is otherwise an evasion oracle.
`unknown` must be a distinct answer from `not-blocked`, where `not-blocked` is a positive assertion backed by
retained records covering the whole window. And queries must be scoped to paths the caller can prove it owns, and
rate-limited with exponential backoff.

**Prior art that makes this reasonable to ask for.** Dev Drive shows Microsoft has already accepted that developer
workloads warrant a declared trust designation with consequences for filter attachment [8], though it is
volume-scoped, format-time only, unavailable on the system drive, and its performance mode applies to Microsoft
Defender alone. App Control already records a kernel-managed extended attribute describing what wrote a file, so
provenance as a file property is not novel in this operating system. And `fanotify` ships the exact
permission-versus-notify split being requested here.

---

## 8. What gets built regardless of adoption

Every user-visible benefit must be reachable with zero cooperation from anyone. If standardisation never succeeds,
and I assume it will not for years, the following still ships.

**Interdiction correlation.** Watch the documented signals a security product already emits, join them to the agent
session that produced the file, and tell the developer plainly that this looks like security-product interference
rather than a compiler bug. Recognise the signature shapes: access-denied on a compiler's own output, a build
artifact that vanished after being written, a run-at-login value that reverted unbidden.

**Attribution.** Bind every process, command and file write to a supervised session, so "which agent did this, under
what task" has an answer.

**Declaration drift.** Compare observed behaviour against the published declaration and surface the difference.
Behaviour beyond the declaration is a signal. An over-broad declaration is itself worth flagging. Needs no vendor
and is testable today.

---

## 9. Project Powersmell

Correlation tells a developer *that* something was interdicted. It does not reduce the ambiguity that caused it.
Project Powersmell attacks that directly and is in development as a drop-in module.

**The problem as a learning problem.** Given a command line, a script body and its process ancestry, decide whether
it is the output of a supervised automation session or unattributed execution. That is a different target from
malicious-versus-benign, and the difference is the point. Existing work separates malicious from benign script
content, and per section 3 agent output sits awkwardly on that boundary by construction. Separating *supervised*
from *unattributed* is a question the supervision context can answer, which makes it learnable and the labels cheap.

**Building on YaraML.** Joshua Saxe and SophosAI published YaraML [2], an open-source toolkit that trains a
classifier on labelled malicious and benign artifacts and *compiles the trained model into human-readable YARA
rules*, using logistic regression or random forest over substring features with feature selection to control
overfitting. Sophos are explicit that it is experimental and that no ruleset is perfectly accurate.

I want to adapt that rather than reinvent it, for one reason above all: **the output is inspectable and portable.**
A vendor cannot deploy my model and should not want to. A vendor can read a YARA rule, argue with it, modify it and
ship it. For a proposal whose premise is that a third party must be able to verify what I am claiming, an
explainable rule artifact is worth more than a more accurate opaque one.

Intended adaptations, all open questions rather than results:

- Retarget the label from malicious-versus-benign to supervised-versus-unattributed.
- Extend features beyond substrings to process-ancestry shape, invocation-flag combinations, inter-process timing,
  and the decoded content of encoded commands. That last matters: in my corpus, eleven distinct encoded blobs all
  decoded to harness wrapper scripts, so feature extraction that stops at the base64 is looking at the wrong thing.
  This is where the deobfuscation approach of Li et al. [1] applies directly, and where adapting their
  semantic-signature method should beat substring features alone.
- Evaluate against a negative corpus, reporting false-positive rate on known-benign agent output as the primary
  metric rather than a footnote.

**Corpus.** The 292 distinct command lines from section 2 are published alongside this paper [10], with usernames,
security identifiers and unrelated project names redacted. Every entry is benign, so a detector that fires on one is
producing a false positive. Nine are marked flagged, which makes them the hard cases, because a shipping product
classified them as malware. I would like other people to add to it. One machine is an anecdote, and I would rather
build the dataset that settles the question than keep arguing from n=1.

---

## 10. Naming, and what was rejected

The name was chosen through structured clearance across 74 candidates, of which 36 survived trademark, product and
acronym collision checks. Recording the rejections matters, because several are traps a later reader would
otherwise walk into.

- **Delegated execution** was the strongest rejected family, and it came closest. Mishra and Sharad [9] use exactly
  this framing for exactly this problem, and delegation names the human-to-software relationship rather than the
  product. It loses on three independent readings, not one. In the Microsoft identity stack, delegation means
  Kerberos constrained delegation and OAuth on-behalf-of, and the "execution" qualifier sharpens that association
  rather than escaping it, since constrained delegation exists so a delegated action can execute downstream. In
  agent tooling it means agent-to-agent handoff. In the identity and academic literature it means an authenticated
  grant of *authority*, which is a direct hit on the one property that must never be misread. The term is retained
  in prose, with the citation, and kept off the box.
- **Execution provenance** is already claimed: a funded vendor markets "the execution provenance protocol" and "the
  system of record for execution attribution" with its own coined category. Adopting it would make the category
  label a competitor's tagline.
- **Delegated Execution Provenance** gives DEP, which is Data Execution Prevention, shipped since Windows XP SP2.
- **Automation Provenance Declaration / APD** was my own provisional artifact term, and is disqualified: APD is
  Attack Path Discovery inside security, which also drags the name toward the antivirus reading.
- **Automation supervision** was my own provisional class term, and is disqualified because *supervision*
  unambiguously implies authority over the supervised party, which is precisely what this class must never claim.
- **Execution sponsorship** was the best Microsoft vocabulary fit and the worst safety reading, because in Entra's
  documentation a sponsor approves and authorises.
- **Coined and Latinate options** were rejected on strategy: the whole approach is to ride vocabulary that already
  exists rather than teach a new word at the moment recognition is the goal.

**The known risk in the chosen name.** Inside Microsoft, "automation" has been captured by Power Platform, so there
is a real chance of misrouting to the wrong team. The mitigation is that *automation* must never travel alone: every
first sentence lands a Windows, endpoint, process or developer-machine noun within a few words. This was chosen with
the cost understood, because the alternative failure is worse. A name that routes to the right team but reads as
"we already ship this" kills a proposed category, whereas a misroute to an adjacent org is recoverable.

**"Provenance" as a bare word is not available** and must never be used as the product name, schema name, or
conversational shorthand. Several companies hold marks on it.

Clearance to date is web-search only. A real USPTO and EUIPO search in Nice classes 9 and 42, plus a common-law
sweep, remains to be done before public launch, along with a check that the name reads sensibly in major languages.

---

## 11. Non-goals

Not an antivirus, not an EDR, not a Security Center participant, not an AMSI provider, not a container or isolation
mechanism, not a configuration manager for anyone else's product, not a second opinion on anyone else's verdicts,
and not a way to make a machine less safe so agents can work. Any exclusion an operator adds is a hole. The job is
to make that hole visible, narrow and temporary, not to open it.

**Honest odds.** I am one developer. The realistic path is to ship the implementation, publish the convention with a
small permissively-licensed reader library so an adopter's cost is an import rather than a parser, gather incident
evidence from more than one machine, and only then approach vendors with data instead of a proposal. Formal
standardisation, if it happens, is ratification of something already working, not the first step.

---

## References

[1] Z. Li, Q. A. Chen, C. Xiong, Y. Chen, T. Zhu, H. Yang. *Effective and Light-Weight Deobfuscation and
Semantic-Aware Attack Detection for PowerShell Scripts.* CCS '19. https://doi.org/10.1145/3319535.3363187 ·
Code: https://github.com/li-zhenyuan/PowerShellDeobfuscation

[2] J. Saxe, SophosAI. *An open source ML toolkit for automatically generating YARA rules.*
https://www.sophos.com/en-us/blog/an-open-source-ml-toolkit-for-automatically-generating-yara-rules ·
Code: https://github.com/sophos/yaraml_rules

[3] Microsoft. *Windows platform security for AI agents*, Windows Developer Blog, 2 June 2026.
https://blogs.windows.com/windowsdeveloper/2026/06/02/windows-platform-security-for-ai-agents/

[4] Microsoft. *What is Microsoft Entra Agent ID?*
https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id

[5] Microsoft. *Microsoft Build 2026: Securing code, agents, and models across the development lifecycle.*
https://www.microsoft.com/en-us/security/blog/2026/06/02/microsoft-build-2026-securing-code-agents-and-models-across-the-development-lifecycle/

[6] Microsoft. *Microsoft Defender Antivirus compatibility with other security products.*
https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility

[7] ISO/IEC 19770-2:2015, *Software identification tag*, and IETF SACM, *Concise Software Identification Tags*
(draft-ietf-sacm-coswid).

[8] Microsoft. *Dev Drive.* https://learn.microsoft.com/en-us/windows/dev-drive/

[9] A. Mishra, K. Sharad. *Observability for Delegated Execution in Agentic AI Systems.* arXiv, June 2026.
https://arxiv.org/pdf/2606.09692

[10] Corpus accompanying this paper: `tests/fixtures/av-corpus/` in github.com/aXL333/TraceBrake.
