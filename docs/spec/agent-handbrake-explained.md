> **Style note.** This is the plain-language companion to
> [The Agent Handbrake, v1.0](agent-handbrake-v1.md), written as a pastiche of Theo Browne's (t3.gg) essay voice
> because that register explains normative documents better than normative documents do. It is not written by
> him, not endorsed by him, and must not be published under his name. Blue Heeler Software, September 2026.

# Your AI agent needs a handbrake, and no, the permission prompt doesn't count

Okay. I need to talk about something that has been bugging me for months, and I finally found a document that says
it better than I've been saying it, so I'm going to walk you through it.

Here's the setup. I run coding agents in yolo mode. Skip permissions, full auto, let it cook. I'm not going to
pretend otherwise, and if you're being honest, a lot of you do too, because the permission prompt is annoying
exactly when the agent is being useful. That's not a character flaw. That's a UX problem. The prompt is the brake,
and the brake is wired to the same foot as the gas, so the moment you're actually going somewhere, you turn it off.

And then you've got nothing.

Not "you've got a weaker brake." Nothing. The agent is spawning shells that spawn shells, compiling stuff, touching
your git config, and the only thing between it and your machine is the same process that's doing the thing. If it
goes sideways, your options are Ctrl+C and hope, or Task Manager and hope harder.

So when I read this spec, the thing that got me wasn't that it proposes a fix. It's that it names the category
correctly. It's not a sandbox. It's not a policy engine. It's a **handbrake**. And once you hear it that way you
can't unhear it.

## The car analogy, because it actually works this time

I usually hate car analogies. This one earns it.

Your car has two brakes. The good one is hydraulic, power-assisted, wired into everything, and you use it a thousand
times a day. The other one is a steel cable you pull with your hand. It is worse in every measurable way except
one: it doesn't care if the good one is broken. Engine dead, hydraulics gone, electrics fried, you can still pull
it, and you can pull it while the car is moving.

Nobody looks at a handbrake and says "well the disc brakes are better so why bother." You fit it because the day
you need it is by definition the day the good brake isn't there.

Every brake AI agents have right now is a service brake. The permission prompt lives inside the agent. The sandbox
is a box the agent has to agree to run in, and the agents doing real work on your machine aren't in a box, because
they need your actual repo and your actual toolchain. Your antivirus? I'll get to your antivirus. Spoiler: it's
braking the wrong wheel from twenty-nine hops away.

What nobody's shipped is the cable.

## The four things that make it a handbrake and not a suggestion

The spec is a real spec. RFC 2119 MUSTs, numbered requirements, conformance classes, the whole thing. But it boils
down to four properties, and if any one of them is missing, you don't have a handbrake, you have a vibe.

### 1. It's a separate mechanism

Not a plugin. Not a hook. Not a system prompt that says "please be careful." A separate process, watching from
outside, that doesn't need the agent's cooperation to see what it's doing or to stop it.

And this is the part people get wrong: it can't require you to launch the agent *through* it. If your safety tool
only works when you remembered to start the car with the safety tool, it's not independent, it's a wrapper, and
wrappers get bypassed the first time they're inconvenient. The spec is explicit: an agent that was started with no
idea the handbrake exists is still fully covered.

Also, and this is the one I'd frame on my wall: the handbrake's guarantees have to be *identical* whether you
started the agent with permissions on or in yolo mode. The whole point is that it doesn't care about the agent's
own settings. That's what independent means.

### 2. The stop is a floor, not a request

When you pull it, stuff stops. Not "a message is sent asking things to stop." Stops.

The spec gets really specific here, and every specific thing is a race someone actually hit. Pending actions get
*rejected*, not paused, because a paused action is a loaded gun that fires the second you release. Every halt gets
a monotonic epoch, so an action that was approved before the stop can't sneak through after it. If the tool is
injecting keyboard and mouse input for the agent, it re-checks the halt before *every single input*, not once per
batch, because a batch is exactly where the bad thing happens. If a key is held down when you pull the brake, it
gets released, so a half-finished drag can't complete on its own. Any helper process it spawned to do the driving
gets killed, not signalled.

And, my favorite: the halt has to work while the UI is frozen, and it can't travel over the same pipe the actions
travel over. Because if the agent can flood the pipe, and your stop signal is in the same pipe, your stop signal is
behind the flood. That's not a brake. That's a suggestion box.

### 3. The agent can't release it

This is the whole thing. This is the section the spec itself calls "the one on which the class rests." A handbrake
with a release button on the accelerator is not a handbrake.

So: no tool, no API, no flag, no config file, no message the agent can send that releases a halt or lowers the bar
for one. The agent can't kill processes through the handbrake, including its own children. The agent can't
acknowledge or dismiss anything serious enough to have triggered a stop. It can clear its own low-severity noise,
sure, and that gets logged as "the agent cleared this," which is the right amount of trust.

And the sneaky one: anything the agent says about *who it is* is treated as a hint about where to send a question,
never as authorization. Because agents lie about their names, or get impersonated, or you're running three of the
same one and they're indistinguishable. The spec straight up says: design as if you can't tell them apart, because
you can't.

### 4. A human releases it, and it has to be a real human

Not a token. Not a session cookie. Not "the process is running as you, so it must be you." Every one of those can
be held by a program, and the thing you're trying to stop is a program running as you.

Live presence. Windows Hello, a hardware key, something a process holding your credentials can't fake on its own.
Bound to *that specific release*, not cached, not replayed from the last time.

And if you haven't set up any presence mechanism? It fails closed. A halt on that machine can only be released by
enrolling one. The spec requires the tool to tell you this *before* the first halt can happen, which is the right
call, because finding out afterward would be a bad day. But the alternative, "release if no authenticator is
configured," is the accelerator button again with extra steps.

## The stuff it's NOT allowed to do

This is where I went from "neat" to "okay, they actually thought about this."

There's a whole prohibited-behavior section, and it's the mirror of the four properties. A handbrake can't also be
an accelerator. So:

- **No `allow` verb.** Nothing an agent can reach whose meaning is permission, exemption, trust, suppress, priority.
  A handbrake "mints no permissions." If your safety tool has an allowlist the agent can touch, it's not a safety
  tool, it's a self-service bypass with a nicer UI.
- **No model gets to pull the brake.** You can route the agent's behavior to a second AI for a second opinion. Love
  it, do it. But that verdict goes to the *human* and stops there. It cannot auto-halt, auto-kill, auto-release,
  auto-anything. Because a second AI is a channel, and a persuasive agent can talk a channel into a favorable
  verdict. Automatic halts are allowed only from boring, deterministic escalation the tool does itself.
- **No sending the agent to review itself** and calling it independent. Obviously. And yet.
- **No touching your antivirus.** It can't add exclusions, it can't register as security software, it can't
  install filter drivers. It's not an AV and it doesn't get to displace one.
- **No zombie persistence.** If something kills it, it can put its startup entry back *once*, then it has to stop
  and tell you. Because a tool that keeps resurrecting itself is, from the outside, indistinguishable from malware.
  This one shows real self-awareness about what kind of software they're building.

The spec's own line: a handbrake that can also accelerate, that another program can release, or that grants passage
to the thing it's meant to stop, is not a worse handbrake. **It is not one.**

## Wait, why isn't my antivirus already this?

Because your antivirus can't see the thing that matters, and the companion paper has the receipts.

They instrumented one workstation. One agent session: 292 distinct command lines across PowerShell, bash, git,
rustc, csc, dotnet, cargo, link, reg. Hundreds of short-lived processes spawned at machine speed, ending in
freshly compiled unsigned binaries. The PowerShell calls all had `-NoProfile -NonInteractive -ExecutionPolicy
Bypass`, because that's how you run PowerShell unattended, and sometimes `-EncodedCommand`, because that's how you
pass a multi-line script safely.

Every one of those flags is also a malware heuristic. Not because the agent is imitating malware. Because the same
constraints produce the same shape.

Their AV built a 130-node process graph off one of those PowerShell calls, labeled the whole chain ransomware, and
at the far end blocked the *Roslyn compiler* from writing a unit-test DLL. Twenty-nine hops from the decision that
mattered, with zero idea which agent issued the command or why. It braked the wheel it could reach.

That's the gap. The information that resolves "is this a build or an attack" lives one layer up, with whatever is
supervising the agent. The AV doesn't have it. The container solutions have it but only inside the container, and
your agent isn't in the container. The handbrake is the thing that sits at the right layer.

## Who this is for

Two conformance classes, and I like that they're independent.

A **conforming handbrake** is the tool. It has to do all of the above, and the spec calls out which requirements
you can test with a race harness (halt lands between two inputs, second one doesn't fire; approved-before-halt gets
refused after; nothing's held down after a stop) versus which ones you can only verify by reading the source (no
code path from anything agent-reachable to release; every release path ends in a presence check with no bypass).

A **cooperating subject** is a harness that chooses to play nice: reports what task it's on, answers when asked to
justify something, doesn't go poking for a release path, doesn't "helpfully" edit the handbrake's config to finish a
task. And here's the line I respect: cooperating *earns the agent nothing* on the release side. It just means the
human gets better questions and better answers. A conforming handbrake has to give every guarantee to an agent that
cooperates with none of it.

## Okay so where's the one I can install

There's one implementation, TraceBrake, Windows-only, alpha, GPL, and the spec's own status line says it does *not*
yet claim conformance, which, respect. It's the thing the spec was distilled from, and it doesn't meet all of it
yet. Concrete example: the spec says the halt has to complete within a *documented* bound. TraceBrake's own design
doc describes the mitigation (about one input's worth of latency, then `BlockInput`, then kill the sidecar) and
lists measuring the actual panic-kill latency as an on-device gate that's still open. That's a structural bound,
not a number, and the spec wants the number. That's the correct order though: build it, learn where it breaks,
write down the shape, then go back and meet the shape.

The spec itself is CC0. Copy it, implement it, ship it in a proprietary product, don't credit anyone. It's short.
It's specific. The four properties are the whole thing and they're not negotiable, and I think that's exactly the
right amount of opinion for a document like this.

Because here's where I land. We have provenance for what got built. We have provenance for what got published. We
have identity for agents in containers and permission prompts inside the agents themselves. What we don't have is a
second, independent, human-only way to stop a machine that's doing things on your actual computer, in your actual
session, at machine speed, in a shape every existing detector reads as an attack.

That's a handbrake. Somebody's finally written down what one is. Go build one, or go use one, but stop pretending
the permission prompt you turned off on day one counts.
