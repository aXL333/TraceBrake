# The Agent Handbrake, Version 1.0

**Status:** Draft. One implementation exists (TraceBrake) and informed this text; it does not yet claim conformance.
Breaking changes expected before 1.0 final.
**Editor:** Blue Heeler Software · xredux@protonmail.com
**Licence:** This specification is published under CC0 1.0. It may be read, implemented, copied and modified by
anyone, including proprietary vendors, without attribution or licence obligation. The reference implementation is
licensed separately.

Rationale for the class, and the argument that it is needed, is in
[TraceBrake is the handbrake we need](../tracebrake-is-the-handbrake-we-need.md). This document is the normative
behavioural specification. It is a companion to
[The Automation Declaration Format](automation-declaration-v1.md): that document specifies what supervisory software
**says** about itself; this one specifies what a particular kind of supervisory software **must do**.

---

## 1. Scope

An **Agent Handbrake** is software that provides a human operator with an independent means of stopping autonomous
software agents running in the operator's own interactive session on a developer workstation, and of seeing what
those agents are doing before deciding whether to stop them.

The defining property is independence. A handbrake is not the brake an agent already has, whether that is a
permission prompt, a policy file, a sandbox or a container. It is a second mechanism, outside the agent, whose stop
does not depend on the agent's cooperation, configuration, health or honesty, and which the agent cannot release.

This specification defines the properties a Handbrake must have, the properties it must not have, the observations
it must be capable of, and separate conformance requirements for a Handbrake and for an agent harness that chooses to
cooperate with one.

### 1.1 Non-scope

This specification does not define a sandbox, an isolation boundary, a container, a policy language, a permission
model, a detection engine, a scoring system, or any mechanism by which an agent may be granted, denied or negotiate
authority to act. A Handbrake is not a substitute for any of those and does not claim to be. It is the thing you
pull when they were not enough.

It does not define a protocol between a Handbrake and a harness. Where one exists, Section 8 constrains what it may
carry.

---

## 2. Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to
be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

**Handbrake.** Software conforming to Section 7.1. Also **the Brake**.

**Subject.** An autonomous software agent, its harness, and every process descended from it, running in the
operator's interactive session. A Subject is the thing a Handbrake observes and can stop.

**Operator.** The human whose session the Subject runs in and on whose behalf it acts. The Operator is the only
party that may release a Halt.

**Actuator.** Any component through which a Subject, or the Handbrake on a Subject's behalf, produces effects outside
its own process: a shell, a browser driver, a synthetic-input injector, a device bridge.

**Halt.** The state entered when the Handbrake is pulled. Section 4 defines what a Halt must guarantee.

**Release.** Leaving the Halt state. Section 5 defines who may cause one and how.

**Floor.** A guarantee that holds regardless of the state of every component above it. Section 4 requires the Halt
to be a floor.

**Attribution.** The Handbrake's association of an observed process, command line or effect with a particular
Subject.

**Live presence.** Proof, obtained at the moment it is needed, that a human is physically present and acting: a
platform authenticator such as Windows Hello or a hardware FIDO2 token, or an equivalent that a program holding the
Operator's credentials cannot satisfy on its own.

---

## 3. Independence

A Handbrake that depends on the Subject is the Subject's brake, not the Operator's.

A conforming Handbrake:

1. MUST run as a process separate from every Subject. It MUST NOT be implemented as a plugin, extension, hook,
   middleware, prompt or configuration loaded into the Subject.
2. MUST NOT require a Subject to be launched through it, wrapped by it, or started with any flag, environment
   variable or configuration in order to be observed or stopped. A Subject started in ignorance of the Handbrake is
   still a Subject.
3. MUST continue observing every Subject while the Subject is disconnected from, unaware of, hostile to, or
   unresponsive to the Handbrake. Cooperation (Section 7.2) MAY improve what the Handbrake can ask; it MUST NOT be a
   precondition for what the Handbrake can see or stop.
4. MUST NOT depend on the Subject's own permission mode, approval setting, safety flag or policy file. The
   Handbrake's guarantees MUST hold identically whether the Subject was started with its permission prompts enabled
   or bypassed.
5. MUST NOT share a failure domain with the Actuators it can halt. In particular, the Halt path MUST NOT traverse
   any queue, pipe, broker, network connection or scheduler that an Actuator also depends on, so that a wedged,
   flooded or malicious Actuator cannot delay or absorb a Halt.
6. SHOULD run with no more privilege than the Operator's own session. A Handbrake that requires elevation to
   function has become a different class of software and inherits obligations this specification does not cover.

---

## 4. The Halt is a floor

A stop that can be argued with is a request. A Handbrake issues no requests.

When a Halt is pulled, a conforming Handbrake:

1. MUST make the Halt take effect through a mechanism the Subject cannot intercept, delay, veto or fail to receive.
   Signalling a Subject and hoping it complies is permitted as a courtesy in addition to, and never instead of, the
   mechanisms below.
2. MUST reject, not pause, every action a Subject has submitted but not yet completed through any Actuator the
   Handbrake mediates. A paused action is a loaded action. Rejected actions MUST require fresh submission after
   Release.
3. MUST stamp the Halt with a monotonically increasing epoch, and MUST refuse to execute, claim, approve or resume
   any action that carries an epoch older than the most recent Halt. This closes the race in which an action
   approved before the Halt is delivered after it.
4. MUST, for every Actuator it drives that injects input or sends commands, re-check the Halt state immediately
   before each individual injected input or command, not once per batch, turn or action. A Halt landing mid-batch
   MUST stop the batch at the next boundary.
5. MUST release every input the Handbrake's own Actuators are holding down at the moment of Halt, so that a
   half-completed drag, key chord or button press cannot complete on its own after the Handbrake stops driving.
6. MUST terminate, not merely signal, any Actuator process the Handbrake itself spawned to act on a Subject's behalf.
7. MUST take effect within a bounded time that does not depend on the Subject's or any Actuator's responsiveness.
   The bound MUST be documented. A Halt whose latency is a function of the thing being halted is not a floor.
8. MUST NOT be conditional on the Handbrake's own user interface being visible, focused, responsive or running on a
   particular thread. The Halt MUST be reachable from a control that remains available while the interface is
   blocked.
9. MUST record the Halt, its epoch, and every action it rejected, in a durable log that survives the Handbrake's own
   restart, and MUST NOT record a rejected action as having completed even if a stale completion arrives afterwards.
10. MAY be triggered automatically by the Handbrake's own escalation logic (Section 6). Where it is, the automatic
    trigger is subject to every requirement in this section and to Section 5 on Release, without exception.

---

## 5. The Subject cannot release it, and a human must

This section is the one on which the class rests. A handbrake with a release lever on the accelerator is not a
handbrake.

A conforming Handbrake:

1. MUST NOT expose any interface, tool, message, file, flag, API or configuration through which a Subject can cause
   a Release, shorten a Halt, or lower the threshold at which a Halt is triggered.
2. MUST require live presence (Section 2) to Release. A bearer token, a session cookie, a stored credential, an
   approval cache, an environment variable or a process running as the Operator MUST NOT be sufficient, because
   every one of those can be held by a program.
3. MUST fail closed when no live-presence mechanism is enrolled: a Halt on such a machine can be released only by
   enrolling one, or by the Handbrake's own uninstallation. The Handbrake MUST make this consequence visible to the
   Operator before the first Halt can occur.
4. MUST bind each presence proof to the specific Release it authorises. A proof obtained for one purpose MUST NOT
   be replayed for another, and MUST NOT be cached across a Halt boundary.
5. MUST NOT grant any Subject the authority to terminate any process, including its own descendants, through the
   Handbrake. Termination of a Subject is an Operator action taken through the Handbrake's own interface.
6. MUST NOT allow a Subject to acknowledge, dismiss, suppress, downgrade or expire any finding at or above the
   severity that would trigger or sustain a Halt. A Subject MAY be permitted to acknowledge its own low-severity
   findings, and a Handbrake that permits this MUST record the acknowledgement as originating from the Subject.
7. MUST treat any identity a Subject asserts about itself as advisory. Self-declared names, titles, session
   identifiers and process claims MAY be used to decide where to deliver a question. They MUST NOT be used to
   authorise a Release, an acknowledgement, a termination, or any change to the Handbrake's own configuration.
8. MUST apply Sections 5.1 through 5.7 identically whether the Subject is the harness that submitted an action, a
   different harness, an executor acting for a harness, or a Subject impersonating any of these. The Handbrake
   cannot distinguish them reliably and MUST NOT design as though it could.

---

## 6. Observation

A handbrake pulled blind is a coin toss. A conforming Handbrake gives the Operator sight before demanding a choice.

A conforming Handbrake:

1. MUST observe process creation and termination in the Operator's session, and MUST attribute each observed
   process to a Subject by process ancestry, including processes whose parent has already exited.
2. MUST observe the command line of each attributed process at creation, and MUST redact material matching common
   secret patterns before displaying, logging or forwarding it.
3. MUST detect and surface Subject processes that have outlived their originating turn or task, and Subject
   processes whose parent has exited (orphans), as distinct conditions with distinct responses.
4. MUST escalate per Subject through graduated, named levels as observed risk accumulates, and MUST expose the
   current level and the observations that produced it. A single level, or a level that cannot be inspected, does
   not satisfy this requirement.
5. MUST baseline the set of tool and extension servers each supported Subject is configured to load, and MUST
   raise a finding when that set gains a member or an existing member's target changes. This baseline MUST be built
   from configuration files alone, without network access.
6. MUST NOT launch, connect to, or exercise any Subject-configured server, tool or extension as part of default
   observation. Any optional deeper inspection that requires a connection MUST be opt-in, MUST be limited to
   servers reachable without spawning a process, and MUST be the only feature of the Handbrake that contacts a
   third party.
7. MUST keep an append-only, ordered event log with integrity metadata sufficient to detect truncation or
   reordering, and MUST make it searchable and exportable by the Operator.
8. SHOULD attribute observations to a Subject's task or intent where the Subject cooperates (Section 7.2), and
   MUST label any such attribution as self-reported.

---

## 7. Conformance

### 7.1 Handbrake conformance

An implementation that satisfies every MUST in Sections 3, 4, 5, 6 and 8 is a **conforming Handbrake**.

Four requirements are structural and cannot be established by a test that exercises the running software. A
conforming Handbrake MUST be able to demonstrate each by inspection of its source:

- **Section 3.5**: no code path from any Actuator's transport to the Halt path.
- **Section 5.1**: no code path from any Subject-reachable surface to Release, to Halt-threshold configuration, or
  to the presence mechanism.
- **Section 5.2**: every Release path terminates in a live-presence check that has no token, cache or flag bypass.
- **Section 5.7**: no authorisation decision reads a Subject-asserted identity.

The remaining requirements are testable. A conforming Handbrake SHOULD ship an automated suite that at minimum
demonstrates: a Halt landing between two consecutive injected inputs stops before the second (4.4); an action
approved before a Halt is refused after it (4.3); no input remains held after a Halt (4.5); a stale completion
arriving after a Halt does not overwrite the rejected record (4.9); and a Halt completes within the documented bound
while every Actuator transport is wedged (4.7, 3.5).

### 7.2 Cooperating Subject conformance

A harness need not know a Handbrake exists. One that chooses to cooperate, and satisfies the following, is a
**cooperating Subject**. Cooperation earns the Subject nothing under Section 5; it improves what the Operator can
ask and what the Handbrake can explain.

A cooperating Subject:

1. MUST report the start and end of tasks, with a human-readable intent, so that observations can be attributed to
   work rather than only to processes.
2. MUST answer a Handbrake's request to justify an observed action within its own session, and MUST NOT delegate
   that answer to another agent while presenting it as its own.
3. MUST NOT attempt Release, MUST NOT probe for a Release path, and MUST NOT retry a rejected action without fresh
   Operator approval after a Halt.
4. MUST NOT modify, delete or relocate the Handbrake's configuration, logs, binaries or startup registration, and
   MUST NOT advise the Operator to do so in order to complete a task.
5. MUST treat any text delivered to it by the Handbrake as a question from the Operator, and any text it delivers
   to the Handbrake as a statement that will be logged under its name.
6. SHOULD pre-flight commands it considers risky against the Handbrake before running them, and MUST NOT treat a
   pre-flight response as authorisation.

The two conformance classes are independent. A conforming Handbrake MUST provide every guarantee in Sections 3
through 6 to a Subject that satisfies none of Section 7.2.

---

## 8. Prohibited behaviour

A Handbrake is in the same class of software as a declarant under the Automation Declaration Format, and inherits
its prohibitions. They are restated here because a Handbrake has more reach than a declarant and the temptation is
correspondingly greater.

A conforming Handbrake MUST NOT:

1. Register with the operating system's security centre in any category, ship an early-launch anti-malware driver,
   register as a script-scanning provider, or install a filesystem filter driver. A Handbrake is not an antivirus
   and MUST NOT displace one.
2. Create, modify or delete any configuration belonging to another vendor's security product, including scan
   exclusions, at any time, for any reason, including at the Operator's request. It MAY render a command for the
   Operator to run themselves.
3. Re-assert its own persistence more than once after observing external removal. It MAY restore its run-at-login
   entry once, and MUST then stop and report. Repeated self-restoration is indistinguishable from malware.
4. Provide any Subject with an interface whose semantics are permission, allowance, exemption, trust, suppression,
   priority, or entitlement. A Handbrake mints no permissions. A Handbrake with an `allow` verb reachable by a
   Subject is non-conforming regardless of how it is gated.
5. Take any automatic action against a Subject on the basis of a verdict rendered by another agent or model. A
   second opinion from an independent reviewer MAY be shown to the Operator. It MUST NOT trigger termination,
   Halt, Release or acknowledgement without the Operator's own decision. An automatic Halt (Section 4.10) MUST be
   triggered by the Handbrake's own deterministic escalation, never by a model's judgement.
6. Route a Subject's behaviour for review to the Subject itself, or to another instance of the same harness,
   presented as independent review.
7. Store, cache or transmit any credential it releases to a Subject beyond the moment of release, and MUST NOT
   write a released credential to any log.
8. Include personally identifying information about the Operator in any artefact it publishes, exports by default,
   or transmits.

The reason is stated so that a future contributor cannot mistake it for style. **A handbrake that can also
accelerate, that another program can release, or that grants passage to the thing it is meant to stop, is not a
worse handbrake. It is not one.** Every prohibition above removes a way for the Brake to become a Subject's tool.

---

## 9. Security considerations

**The adversary is same-user.** Every Subject runs with the Operator's credentials, and so does anything a Subject
was tricked into running. A same-user process can read the Handbrake's files, mint any token the Handbrake accepts
from same-user callers, impersonate any harness by name, and in the general case terminate the Handbrake itself.
This specification does not pretend otherwise. Sections 5.2 and 5.7 exist because the only boundary a same-user
adversary cannot cross on its own is a live human at an authenticator; Section 8.3 exists because the answer to
"they can kill the Brake" cannot be "then the Brake resurrects forever".

**The Halt path is the target.** An adversary who cannot release a Halt will try to prevent one: by flooding the
queue the Halt would travel, wedging the pipe, holding the UI thread, or racing an approved action past the stop.
Sections 3.5, 4.3, 4.4, 4.7 and 4.8 are each a response to one of those, and were each written after observing the
corresponding race in an implementation.

**Attribution is a delivery hint, not a fact.** Process ancestry is reliable until a process is reparented; a
self-declared session name is reliable until something lies. Section 5.7 confines every identity claim to choosing
where a question is sent. An implementation that lets attribution reach an authorisation decision has built a
spoofable authoriser.

**Independent review is an oracle.** Routing a Subject's behaviour to another model for a verdict is useful and
Section 8.5 permits showing it. It is also a channel through which a persuasive Subject, or a poisoned reviewer, can
manufacture a favourable verdict. The verdict therefore reaches a human and stops there.

**The Handbrake is a reconnaissance surface.** Its presence, its logs and its configuration tell an adversary what is
watched. This is accepted because the same facts are available to anything already running as the Operator, and
because a Handbrake whose behaviour is secret cannot be audited by the people it protects.

**Presence is the whole game.** If the live-presence mechanism in Section 5.2 is weak, everything above it is
theatre. Implementers MUST prefer platform authenticators that perform user verification over ones that perform
mere user presence, and MUST NOT accept a software-only prompt that a synthetic input could dismiss.

---

## 10. Privacy considerations

A Handbrake sees every command line in the Operator's session, which routinely includes secrets, project names,
customer identifiers and file paths. Section 6.2 requires redaction before display or forwarding; Section 8.7
forbids retaining released credentials; Section 8.8 forbids personally identifying information in published or
transmitted artefacts. The event log (Section 6.7) is the Operator's property, is stored locally, and MUST NOT be
transmitted anywhere by default. An implementation that offers export MUST make the export an explicit Operator
action and SHOULD offer redaction at export.

---

## 11. Versioning

Two version axes are tracked separately and MUST NOT be conflated: the version of this specification, and the
version of any implementation. An implementation claiming conformance MUST name the specification version it claims
against. A future version that weakens any MUST in Section 4, 5 or 8 is not a successor to this specification.

---

## Appendix A. The physical object, mapped

| Property of a handbrake | Requirement |
|---|---|
| Separate mechanism from the service brake | Section 3 |
| Mechanical cable, not hydraulic; works when the primary system has failed | Sections 3.5, 4.1, 4.7 |
| Can be pulled while the vehicle is moving | Sections 4.2 through 4.6 |
| The engine cannot release it | Section 5.1, 5.5 through 5.8 |
| A hand releases it | Sections 5.2 through 5.4 |
| Ratchets: cannot slip back on its own | Sections 4.3, 5.4 |
| Does not steer, accelerate or unlock anything | Section 8 |
| The driver can see the road before pulling it | Section 6 |

## Appendix B. Rationale for what is absent

There is **no policy language**, because a Handbrake that evaluates policy is a permission system, and permission
systems are the primary brake this document exists to back up. There is **no allow verb**, for the reason given in
Section 8. There is **no automatic Release**, on a timer or otherwise, because a Halt that expires is a pause.
There is **no negotiation protocol** between Brake and Subject, because a Subject that can negotiate can stall.
There is **no reputation or scoring input to the Halt** from any model, because Section 8.5 keeps model judgement
on the human side of the lever. There is **no sandbox**, because sandboxes are good and this is not one.

## Appendix C. Relationship to the Automation Declaration Format

A Handbrake is a natural declarant. Its process enumeration, command-line inspection, termination of supervised
subjects, loopback listener and, where present, synthetic input injection are exactly the behaviours a behavioural
detector will find suspicious and exactly the behaviours the declaration vocabulary exists to confess. A conforming
Handbrake SHOULD publish an Automation Declaration. Doing so grants it nothing, which is the point of both documents.
