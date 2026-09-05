# TraceBrake is the handbrake we need

**Blue Heeler Software** · Draft 0.1 · September 2026

---

A handbrake is not the brake. That is the whole point of it.

The service brake is the one you use a thousand times a day. It is hydraulic, it is boosted, it is wired into the
same systems that make the car go, and it is operated by the same foot that operates the accelerator. It is
excellent. It is also the thing that fails when the thing it depends on fails. So every car ships a second brake
that is deliberately worse in every way except one: it is a steel cable, it is pulled by hand, it is independent of
the engine, the hydraulics and the electrics, and it works while the car is moving. Nobody confuses it with the
service brake. Nobody argues it should be removed because the service brake is better. You fit it because the day
you need it is precisely the day the good brake is not available.

AI coding agents on developer workstations do not have one. TraceBrake is my attempt to fit it.

## What the car is actually doing

Start with what an agent looks like from the machine's point of view, because the metaphor only holds if the
machine is really moving.

On the workstation I instrumented, one agent session produced 292 distinct command lines across `powershell.exe`,
`bash.exe`, `git.exe`, `rustc.exe`, `csc.exe`, `dotnet.exe`, `cargo.exe`, `link.exe` and `reg.exe`. Hundreds of
short-lived processes, spawned programmatically rather than typed, at machine speed, terminating in freshly
compiled unsigned binaries. The PowerShell invocations carried `-NoProfile -NonInteractive -ExecutionPolicy Bypass`
and, when a script would not survive one argument's quoting, `-EncodedCommand`. Every one of those flags is
load-bearing for a program that runs other programs unattended. Every one of them is also a reasonable heuristic
input for a malware detector, because malware wants the same properties for adjacent reasons.

That is a build machine. Viewed without attribution, it is also a fair description of an intrusion. The agent is
not imitating malware. It converged on the same shape because the same constraints apply. I have written this up
at length elsewhere as harness output ambiguity; here I only need the conclusion. The car is moving, fast, and the
person in the driver's seat is a program.

## The brakes we already have, and what they brake

There are three brakes on offer today. Each is a service brake, and each brakes the wrong thing.

**The endpoint security suite.** It sees the stream of processes and it acts. On my machine it built a 130-node
process graph, 129 transitions deep, rooted at the agent's PowerShell call, classified the whole chain
`Malware, Ransomware`, and at the far end denied the Roslyn compiler server permission to write a unit-test DLL.
The detector was not badly built. At the level it observes, that chain and a real one are indistinguishable. But
notice what it stopped: a compiler, twenty-nine hops from the decision that mattered, with no idea which agent
session issued the command or under what task. It braked the wheel it could reach.

**The container.** Microsoft's Execution Containers commit that Windows will attribute all activity inside the
container to an agent identity, so you can tell human from agent. That is the right idea and I am glad it exists.
It is also container-scoped, and the coding agents that produced the incidents above run in the developer's own
interactive session, because they need the real repository, the real toolchain and the real build. A brake on a
vehicle the agent is not driving.

**The harness's own permission prompt.** This is the one people point to, and it is the most important service
brake we have. It is also operated by the same foot as the accelerator. The prompt lives inside the agent process.
It runs under the agent's permission mode. It is bypassed by the same `--dangerously-skip-permissions` flag that
people reach for the moment it becomes annoying, which is to say the moment the agent is doing a lot, which is to
say the moment you most want a brake. And it cannot see what it did not itself issue: the child of the child of the
shell it spawned, the process that outlived the turn, the MCP server that quietly appeared in the config file. A
harness cannot be its own handbrake for the same reason a driver cannot be their own seatbelt.

None of these is wrong. They are just not the second brake.

## What a handbrake looks like in software

Take the properties of the physical object and translate them honestly.

**It is a separate mechanism.** TraceBrake is a tray application. It is not a plugin, not a hook inside the
harness, not a wrapper you launch the agent through. It watches the agent's process tree from outside, attributes
every spawned shell and child and orphan back to the harness that produced it, and keeps doing so whether or not
the harness is cooperating, connected, or alive. When the harness is connected over its local MCP server, TraceBrake
can ask it questions and deliver prompts into its own session. When it is not, the watching continues regardless.
A cable, not a hydraulic line.

**It has a lever, and the lever is a hard floor.** Escalation in TraceBrake is graduated: Watch, then Alert, then
Alarm, then Emergency, as risk accumulates per agent. But above the ladder sits one control, the panic stop, and it
is built so that nothing downstream can argue with it. For mediated computer use, a halt is an access-controlled
memory-mapped flag flip, an auto-reset event, `BlockInput`, a synthetic release of every held key and mouse button
so a half-completed drag cannot finish, and `TerminateProcess` on the sidecar doing the driving. Every pending
action is rejected and stamped with a panic epoch so a stale one cannot be resurrected after the fact. Before every
single injected input the sidecar re-reads that flag. The panic path does not depend on the pipe, the queue, the
broker, or the good behaviour of anything it is stopping. That is the steel cable.

**The thing being stopped cannot release it.** This is the property people forget, and it is the one that separates
a handbrake from a suggestion. A harness connected to TraceBrake can acknowledge its own Low and Medium alerts. It
cannot acknowledge High or Critical; the tool refuses. It has no kill authority, none, over any process including
its own children; killing is an operator action in the UI. Resuming after a panic stop goes through Windows Hello,
so the human who releases the brake has to be a live human at the keyboard, not a token holder and not a model that
learned the API. And because a session's claimed identity is self-declared and spoofable, TraceBrake treats
attribution as advisory only: it decides where to deliver a question, never whether to authorise an action. A
handbrake with a release button on the accelerator is not a handbrake.

**It brakes the right thing.** When TraceBrake raises an alert it knows which agent, which session, which command,
which child. That gives the operator two responses the endpoint suite structurally cannot offer. Ask Harness sends a
second-person prompt into the offending agent's own session: account for this, abort it or explain it. Send for
Audit routes the behaviour to a different agent or API for a second opinion, with self-audit excluded by policy.
Both are human-initiated. Neither is automatic. The point of a handbrake is that a person pulls it, having looked.

**It watches the supply chain too.** A handbrake on a car whose brake lines can be swapped while you drive is not
much of a guarantee. So TraceBrake baselines the MCP servers each harness is configured with and raises an alert
when a new or changed one appears, and can optionally connect to HTTP MCP servers and scan their tool descriptions
for the injection vocabulary that turns a tool into an instruction: ignore previous instructions, hide this from the
user, pipe to shell. That scan is opt-in and is the only feature that touches a third-party server. It never
launches a stdio server. TraceBrake does not spawn what it audits.

## What it deliberately is not

Here is where the metaphor earns its keep, because it forces honesty about limits.

TraceBrake is not a sandbox. It is not a policy enforcement boundary. It does not pretend to be one, and the README
says so in the second paragraph. A determined same-user process can mint a token; a self-declared session name can
lie; a monitor that runs as the user can in principle be killed by the user. A handbrake will not stop a car that
has already left the road. It gives the driver a second, independent way to stop the car while it is still on it.

It is alpha. It is Windows 10 and 11 only today. It is GPL-3.0. It began life as Foreman Agent Safety and was
entered under that name at OpenAI Build Week; the rename is a rename, not a rewrite, and the submission snapshot is
preserved immutably as evidence of what existed when.

And it grants nothing. The provenance work that sits beside it, the signed Automation Declaration, has no `allow`,
`exempt` or `trust` field in its schema, on purpose, so that a declarant cannot ask for an exemption even if it
wants to. It mints confessions, not permissions. TraceBrake's stance is the same. It does not tell your antivirus to
stand down. It does not tell your harness it may proceed. It tells you, the person, what the machine is doing and
gives you one lever that works regardless.

## Why "we"

The title says the handbrake we need, not the one I built, and I mean the pronoun.

The industry has provenance for what was built: SLSA. It has provenance for what was published: C2PA. It has
container-scoped identity for agents that run in containers. It has permission prompts that live inside the thing
they permit. What it does not have is a second, independent brake for what a machine did on a developer's own
machine, in the developer's own session, at machine speed, in a shape that every existing detector reads as attack.

Someone will build a better one than TraceBrake. I hope they do, and the source is open so they can start from
mine. But the shape is not negotiable. It has to be a separate mechanism. Its stop has to be a floor, not a
request. The thing it stops must not be able to release it. And a human has to be the one who pulls it.

That is a handbrake. Fit one.

---

*TraceBrake is at github.com/aXL333/TraceBrake. The shape described above is written down as a normative,
CC0-licensed specification, The Agent Handbrake, under `docs/spec/agent-handbrake-v1.md`, so that anyone can build
one and claim conformance. Automation Provenance, the companion paper, is in the same repository under
`docs/whitepaper-automation-provenance.md`. Contact: xredux@protonmail.com.*
