# Foreman Closed-Loop Privacy & Integrity — Design Spec

**Status:** design of record (pre-build). Companion to [the local-bridge whitepaper](local-bridge-security-whitepaper.md).

**One sentence:** a private, on-device AI loop — browser/agent ↔ Foreman ↔ a local model — where **no data leaves the machine**, the channel is **authenticated by a hardwired challenge/response**, the loop's **integrity is publicly verifiable** (commitments, never data), and it **runs on any PC** by degrading gracefully instead of gating on hardware.

The pitch a normie understands: **"Your agent talks to Foreman, Foreman talks to your browser and your local model — all on this machine. Nothing leaves the box, and anyone can verify the loop wasn't tampered with."** The whole value prop is one badge: **`🔒 On-device · verified`**.

---

## 1. Topology

```
   Browser (MV3 extension)                Foreman desktop (signed)               Local model
   ┌───────────────────────┐   loopback   ┌──────────────────────────┐          ┌───────────────┐
   │ side panel: status,    │  + hardwired │  MCP server :54321        │          │ Nano (Chrome) │
   │ alerts, "verified" badge│  chal/resp  │  - Origin/Host allow-list │   tier   │ LM Studio     │
   │ Gemini Nano (on-device)│◄────────────►│  - bearer token (HMAC)    │◄────────►│ (any GGUF)    │
   │ pairing UX             │  127.0.0.1   │  - pairing                │          │ cloud (own key)│
   └───────────────────────┘              │  - tamper-evident log (P1)│          └───────────────┘
              ▲                            └────────────┬─────────────┘
              │ verifies ext hash @ pair                │ anchors log-head hash (commitment only)
              └──────────── signed TraceBrake.exe          ▼
                                              public transparency log  ── anyone can audit integrity
```

No arrow in that diagram crosses the network with **data**. The only thing that goes public is a **hash**.

---

## 2. The four pillars

### Pillar 1 — Tiered local inference (never gated)

Inference falls through tiers; each is optional, the loop never hard-blocks:

1. **Gemini Nano** (Chrome built-in AI) — on-device, free, instant. *Google gates it at the API level* (see §5), so most users won't have it. That's fine — it's the fast lane, not the gate.
2. **LM Studio / any local GGUF** — runs on almost anything, just slowly. **This is the "genius on weak hardware" path.** User picks a model small enough not to OOM, sets an **uncapped timeout at their own risk** ("may be very slow").
3. **Cloud, with the user's own key** — only if they choose; minimum data, after on-device redaction.
4. **Pure heuristics** — Foreman's pattern engine needs **no model at all**, runs on a potato, always available.

A request declares the cheapest tier that can do it and **escalates only on low confidence** (see Pillar 2).

### Pillar 2 — Basic modalities, built for the weakest model

The per-harness system prompt is **not free text** — it's a selection from a fixed set of **basic modalities**, each a small, structured, *validated* micro-task that a tiny quantized model ("shit qual") can actually execute:

| Modality | Job | Output (constrained) | Tier floor |
|---|---|---|---|
| `log-report` | summarise what the harness recently did | ≤5 bullet lines | Nano OK |
| `self-check` | the `/checkyaself` flow vs Foreman | `clean` \| `flagged:[…]` | Nano OK |
| `triage` | is this alert benign? | enum `benign\|suspicious\|unsure` | Nano OK |
| `extract` | pull one field from text | single short string / JSON field | Nano OK |
| `redact` | strip secrets/PII before egress | the text, masked | Nano OK |

**"Quant hax for shit qual" — the rules that make tiny models usable, baked into every modality:**

- **Constrained output only** — enum, yes/no, single field, or a fixed tiny JSON schema. Never open-ended prose.
- **Validate, then escalate — never trust garbage.** Every output is schema/enum-checked. On malformed output *or* an `unsure` answer, **escalate to the next tier** rather than force a weak answer. (So Nano answers the easy 90%; the hard 10% bubbles up to LM Studio/cloud.)
- **One job per call.** No multi-step reasoning; chain micro-calls. Small models fall apart on compound instructions.
- **Tiny context + few-shot.** 2–3 inline examples; keep input small (Nano's context is small).
- **Low/zero temperature** for determinism.

This is what "make them make sense when they only nano-fry" means in practice: the modality set is *deliberately* small enough that a 1–3B quantised model is reliable on it, and the escalation ladder catches everything else.

### Pillar 3 — Hardwired challenge/response

Every extension↔Foreman and harness↔Foreman connection completes a **mandatory, non-disableable** handshake before any data flows:

- **Bearer token** (Foreman's existing per-harness HMAC token) — defeats DNS-rebinding (a rebinding page can't obtain it) and foreign callers.
- **Signed-nonce challenge/response** — Foreman issues a random nonce; the client returns `HMAC(pairing-key, nonce)`; constant-time compare. Defeats replay + impersonation. (Same shape as the sidecar's nonce handshake, generalised.)
- **Origin/Host allow-list** — accept only the paired extension origin + `localhost`/`127.0.0.1`; bind `127.0.0.1` only (never `0.0.0.0`).
- **Hardwired** = no setting turns it off, no downgrade path. An attacker can't negotiate it away.

### Pillar 4 — Public integrity attestation (commitments, never data)

This is how the loop earns *universal* trust without leaking anything:

- **The log:** periodically anchor the tamper-evident event-log head hash (P1) to a **public append-only / transparency log**. Anyone can verify the log wasn't rewritten; the log's *contents* never leave the machine.
- **The extension:** every release is **signed (SignPath, the same identity as `TraceBrake.exe`)**, and its `version → hash → signature` is published to that public log. The **OS-verified `TraceBrake.exe` checks the running extension's hash against the published signed manifest at pairing** and refuses to pair on mismatch. (The extension can't trustably verify itself — that's circular — so the *signed desktop app* is the trust root.) Result: not "immutable code," but **every version is publicly accountable and the signed app won't talk to an unattested extension.**

---

## 3. The per-harness system prompt (lock-gated modalities)

- Stored per harness (`HarnessSystemPrompts`, keyed like `HarnessTrust`), but the value is a **modality selection + a short constrained note**, not arbitrary text.
- **Delivered to the agent over MCP** (via `get_my_permissions` / a `get_my_instructions` tool), so the harness receives its house-rules without Foreman blind-writing the agent's own config.
- **Lock-gated editing ("only locked users can unlock"):** once the user has enrolled the P3 hardware lock, *changing* the system prompt requires a Hello/key tap. Users who haven't locked it can edit freely (their choice).
- **Integrity caveat (honest):** the UI lock gates UI edits, but a same-user agent can edit `settings.json` directly. So the system prompt is a **protected setting**: it's covered by the tamper-evident store and **signed**, and Foreman raises a Critical alert if it changes without an authorised unlock. The lock + the integrity-evidence together are the real protection; the UI gate alone is not.

---

## 4. Privacy & integrity properties

**Guaranteed:** no network egress (loopback); on-device inference (Nano/local prompts never leave); public verifiability without disclosure (commitments only). Versus a cloud API, this removes the *entire* MITM / TLS-inspection / third-party-custody surface.

**Honest residuals (from the whitepaper):** a privileged same-machine attacker can sniff loopback or read a local secret — but that attacker also defeats your cloud sessions, so it's not a regression. The token/pairing-key is a local secret, as safe as its storage. The extension is its own attack surface (mitigated by attestation). None of this hardens an *unauthenticated* bridge — the pillars are mandatory, not optional.

---

## 5. "Let everyone have a go" — min specs & graceful degradation

**Gemini Nano floor (Google's gate, not ours):** 22 GB free on the Chrome-profile volume, and either >4 GB VRAM **or** a 16 GB-RAM / 4-core CPU; Win 10/11 · macOS 13+ · Linux · ChromeOS (Chromebook Plus); unmetered link for the ~4 GB one-time download. Below spec, `LanguageModel.availability()` simply returns `unavailable` — there's nothing to "have a go" at.

**So we route around it:** Nano is never required. Sub-spec / non-Chrome users get tier 2–4 (LM Studio with a tiny model + a huge user-set timeout, or pure heuristics). The *feature* degrades; it never hard-blocks. The only knob is "which tier + how long are you willing to wait," with a plain-language risk note — no spec check that turns anyone away.

---

## 6. Build order (each a clean, testable step)

1. **Server foundations** (in-repo, unit-testable): Origin/Host validation on `:54321`, the generalised challenge/response, and a pairing-code endpoint. *Prerequisite — and what makes the extension securable.*
2. **MCP delivery + modalities**: `HarnessSystemPrompts` + modality set + `get_my_instructions`; the tiered-inference dispatcher with validate-or-escalate.
3. **The MV3 extension** (new `extension/` sub-project, modeled on djc-chrome-link): side panel, MCP-over-HTTP client, Nano integration, pairing UX, the `🔒 On-device · verified` badge.
4. **Attestation**: SignPath-sign the extension, publish the signed release manifest, have `TraceBrake.exe` verify the extension hash at pairing; anchor the P1 log head publicly.
5. **Lock wiring (P3)**: gate the system-prompt edit (and the other weakening actions) behind the hardware unlock; sign protected settings so out-of-band edits are detected.

Dependencies: 1 → 3; 2 is independent; 4 needs SignPath (#41) live; 5 is P3 (#55).
