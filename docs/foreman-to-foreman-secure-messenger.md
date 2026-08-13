# Foreman-to-Foreman secure messenger

Status: proposed specification and delivery roadmap

Date: 5 August 2026

Audience: Foreman maintainers, security reviewers and future protocol implementers

## Executive decision

Build Foreman Messenger as a new peer protocol, not as a remotely exposed version of the local MCP server or Ask Harness queue.

Version 1 should provide direct, mutually authenticated messaging between two paired Foreman installations. It should work over a LAN, VPN or manually configured endpoint, keep a durable encrypted outbox while a peer is offline, and deliver when both peers are reachable. It should support text, typed task and audit requests, replies, receipts and bounded repository references.

It must not let a remote Foreman directly run tools, approve local actions, change settings, use secrets, control a browser or device, or impersonate a local operator or harness. A remote request may create a clearly labelled, untrusted local Ask Harness item; the receiving Foreman and its local policy remain the only authority.

A hosted relay, file transfer, group conversations and remote action execution are deliberately outside the first release. A later relay can add application-layer end-to-end encryption without changing the local trust model.

## Why this design

Foreman already has useful local messaging semantics:

- `request_harness_review` authenticates the local caller, constrains sender and target identities, redacts and bounds text, and wraps harness mail as untrusted content.
- Ask Harness maintains request identities, lifecycle states, replies and best-effort live delivery.
- Foreman's security event log provides local append-order truth and hash-chained metadata.
- Presence Lock, Guardian-sealed settings and the Vault provide local approval and protected-storage primitives.

Those are good semantics to reuse, but not a network security protocol. The current MCP token is a same-user, local-machine bearer credential. It must never leave its Foreman installation. The existing browser pairing code is also intentionally local and uses a short-lived human code suited to a loopback extension, not remote machine identity.

The messenger therefore needs its own identity keys, pairing ceremony, transport, durable store, replay protection and peer policy.

## Goals

1. Let an operator securely pair two Foreman installations and understand which machine they paired.
2. Authenticate both peers and protect message confidentiality and integrity in transit.
3. Preserve sender identity assertions without confusing them with local authority.
4. Provide reliable, idempotent delivery across restarts and temporary disconnection.
5. Keep stored message content encrypted and keep plaintext out of the security event log.
6. Reuse Ask Harness safely so local agents can receive and reply to remote requests.
7. Give operators simple controls to inspect, pause, restrict, unpair and block peers.
8. Preserve Foreman's Windows 10 and Windows 11 support.
9. Leave a clean path to an untrusted relay and stronger conversation cryptography later.

## Non-goals for version 1

- No public internet relay or store-and-forward service.
- No group chat or multi-device identity synchronisation.
- No attachment transfer; only bounded typed references and links.
- No remote MCP calls, Computer Use, ADB, Vault access, process control or settings changes.
- No remote operator approval. “Approved by the remote operator” is evidence, not local approval.
- No certificate-authority or DNS-based identity model.
- No export, backup or roaming of identity private keys.
- No claim of anonymity, traffic-analysis resistance or post-compromise security.
- No home-grown cryptographic primitives.

## Security properties and invariants

These are design requirements, not implementation suggestions:

1. **Local credentials stay local.** MCP bearer tokens, Vault keys and Guardian material never cross the messenger boundary.
2. **Authentication is not authorisation.** A valid peer connection proves possession of a pinned peer key; it does not authorise an action.
3. **Remote content is untrusted data.** It never becomes a system prompt, command line, executable path or local approval.
4. **No direct execution.** A network message can only enter a durable inbox and, if policy permits, create a locally wrapped request.
5. **Pairing and trust elevation require local presence on both machines.** Neither a harness nor the remote peer can silently grant itself more trust.
6. **The receiver acknowledges only after durable storage.** A sender may retry; the receiver must deduplicate safely.
7. **Replay state survives restart.** Message identifiers and sequence windows are durable.
8. **Remote time is never ordering truth.** Local append sequence is authoritative; timestamps are display and correlation labels.
9. **Message bodies stay out of security telemetry.** Events record bounded metadata and hashes only.
10. **Remote severity cannot mint local Critical events or evict local safety evidence.** Local code assigns local severity.
11. **Protocol downgrade fails closed.** Unknown mandatory fields, unsupported major versions and invalid negotiation terminate the connection.
12. **Missing or degraded evidence is not reported as healthy.** Key-store, mailbox, audit and revocation failures surface explicitly.
13. **A trust signal cannot come solely from attacker-authored content.** Peer identity, harness binding and approvals use local records and cryptographic proof.
14. **Security-state loss fails closed.** A missing, corrupt or rolled-back peer or replay store after initialisation cannot be mistaken for a safe first run.

## Threat model

### Assets

- Foreman peer identity and trust records.
- Message confidentiality, integrity, sender attribution and ordering.
- Local operator attention and approval state.
- Local harness identity and routing.
- Inbox, outbox, receipts and security evidence.
- Availability of Foreman and its safety surfaces.

### Adversaries in scope

- A network attacker who can observe, intercept, replay, delay, reorder or redirect traffic.
- A malicious or compromised remote Foreman.
- A malicious remote harness attempting to impersonate another harness or operator.
- A local same-user process attempting to steal fallback key material or alter peer policy.
- An attacker who obtains a pairing invitation or tries to race the intended peer.
- Malformed, oversized or high-volume input intended to crash, wedge or starve Foreman.
- Clock rollback, restart, disk-full and crash-at-boundary failures.

### Limits

Foreman's existing same-user boundary still applies. TPM/CNG non-exportable keys materially improve resistance to key extraction, but a fully compromised local user session can still interact with the installed application and its UI. A DPAPI fallback is weaker and must be shown as a degraded posture, not described as hardware-backed security.

## Trust model and terminology

- **Foreman peer:** one installation identified by a long-lived public key fingerprint.
- **Peer ID:** `fmn1-` plus a human-displayable encoding of the SHA-256 hash of the identity public key's SubjectPublicKeyInfo.
- **Local principal:** the local operator or a locally authenticated harness.
- **Remote actor assertion:** the remote Foreman's signed/authenticated statement that its operator or a named harness originated a message.
- **Local policy:** the receiving operator's rules for accepting, displaying and routing that peer's messages.
- **Local approval:** an approval obtained on the receiving machine under its Presence Lock policy.

The UI must never collapse these concepts. A message might read:

> From **Axel's desktop Foreman** · asserted actor **Codex** · peer-bound harness · remote operator approval: claimed · local approval: not granted

## Proposed architecture

```text
Local harness / operator
        |
        v
Scoped local Messenger API
        |
        v
Policy + envelope builder ---> encrypted durable outbox
        |                              |
        |                        retry scheduler
        |                              |
        +------------------------------v
                          F2F transport endpoint
                          mTLS + pinned peer key
                                      |
                              untrusted network
                                      |
                          mTLS + pinned peer key
                                      v
                          frame and replay checks
                                      |
                              encrypted durable inbox
                                      |
                         local policy + safe adapter
                                      |
                         UI and/or wrapped Ask Harness
```

Use separate components and trust boundaries:

- `Foreman.Core/Messaging`: envelopes, identifiers, policies, state machines, replay windows and codecs.
- `Foreman.Transport` (new project): listener, connector, TLS, framing, peer verification and optional discovery.
- `Foreman.App/Messaging`: identity protection, encrypted mailbox, pairing and messenger UI.
- `Foreman.McpServer`: scoped local tools and an adapter to Ask Harness; no raw network handling.

The transport project should depend on Core abstractions, not the desktop UI or MCP host. This also preserves a future path to non-Windows clients.

## Identity and key protection

Each Foreman installation creates one ECDSA P-256 identity key and a short-lived self-signed TLS certificate containing that public key. P-256 is recommended for the first implementation because it is broadly supported by Windows CNG, Schannel and .NET across Foreman's target operating systems.

Key storage order:

1. Prefer a non-exportable CNG key in the platform cryptographic provider, using hardware protection when available.
2. If unavailable, store an encrypted PKCS#8 key protected with DPAPI CurrentUser plus a narrow file ACL.
3. Record the active protection class and show a persistent degraded-security badge for the fallback.
4. Keep messenger, Vault, MCP and settings-seal keys in separate derivation and storage domains.

Certificates may renew while retaining the same public key and Peer ID. Identity-key rotation creates a new Peer ID and requires re-pairing. Version 1 should not export or back up identity private keys; replacing a machine means pairing it again.

This peer-identity certificate is not a commercial code-signing certificate and must not be used as one. Binary signing and Guardian integrity checks remain a separate decision about whether the local Foreman code is trusted; peer pinning proves only which installation key answered the connection.

Do not accept a certificate because it chains to a public root or matches a hostname. Verify that its public-key fingerprint matches the locally pinned peer record, that its key use and algorithm are acceptable, and that the peer is not blocked or revoked. Re-evaluate the local peer record on every connection, including resumed sessions. If the platform cannot guarantee that, disable session resumption for v1.

## Pairing ceremony

Pairing is explicit, short-lived and two-sided:

1. The inviter opens **Messenger > Add Foreman** and passes Presence Lock.
2. Foreman creates a single-use 128-bit-or-stronger invitation secret, invitation ID, expiry, inviter Peer ID and endpoint hints.
3. The operator transfers the invitation as a QR code, deep link or complete high-entropy text. Do not use a six-digit remote pairing code.
4. The receiving operator imports the invitation and passes Presence Lock locally.
5. The peers establish a provisional connection, prove possession of their private keys and prove knowledge of the invitation secret without transmitting it. The proof binds both identities, endpoints, protocol version and fresh nonces into the transcript.
6. Both screens display the same short authentication string derived from the complete transcript and show the full fingerprints on demand.
7. Both operators confirm the match. Only then does each Foreman pin the other peer and persist a default receive-only policy.
8. The invitation is burned after success, expires after at most five minutes and is rate-limited by source and invitation ID.

An invitation is a bootstrap secret, not the durable identity. Theft of an unused invitation is mitigated by the two-screen transcript confirmation. A future manual low-bandwidth mode should use a reviewed PAKE rather than weakening the invitation entropy.

LAN discovery may advertise an endpoint and claimed Peer ID on private networks, but discovery is never trusted and never completes pairing. It should be opt-in and disabled on Public network profiles.

## Transport

Use .NET `SslStream` with mutual certificate authentication and the ALPN value `foreman-f2f/1`.

- Prefer TLS 1.3.
- Support TLS 1.2 only where the operating system requires it, with ECDHE and an AEAD cipher suite.
- Reject TLS 1.0, TLS 1.1, static RSA key exchange, CBC suites, null encryption and renegotiation.
- Do not enable TLS 1.3 0-RTT; replayable early data is unsuitable for messages.
- Disable TLS-level compression and do not add application compression in v1.
- Bind the protocol version and both peer identities into the application `HELLO` exchange.
- Perform an application challenge/response after TLS so possession of the expected key, the selected protocol and the live local peer-policy epoch are all checked before frames are accepted.

On Windows, Schannel and enterprise policy influence the available TLS 1.2 suites. The connection must inspect the negotiated protocol, key exchange and cipher and reject anything outside the protocol allow-list; it must not assume that requesting TLS 1.2 automatically selected ECDHE plus AEAD.

The listener is off by default, uses a separate endpoint from MCP, and binds only to explicitly selected interfaces. Firewall creation must be opt-in and limited to Private profiles by default. Binding to all interfaces or a Public profile requires a conspicuous warning and fresh Presence Lock approval.

Direct v1 operation supports:

- same-machine development using isolated test identities and ports;
- LAN connections;
- private VPN/overlay addresses such as Tailscale;
- manually entered IP or DNS endpoints.

The protocol must handle IPv4, IPv6 scope identifiers, endpoint changes and DNS results that change between validation and connection without letting DNS or discovery replace certificate pinning.

## Framing and encoding

Use a four-byte network-order frame length followed by deterministic CBOR. Canonical encoding makes test vectors, hashes and a future signed relay envelope predictable.

- Maximum frame size: 64 KiB in v1.
- Maximum text body: 32 KiB after UTF-8 decoding and normalisation.
- Reject indefinite-length, duplicate-key, excessive-depth and non-canonical security-critical structures.
- Unknown optional fields may be retained or ignored; unknown mandatory fields terminate the message or connection as specified by the protocol version.
- Allocate only after the length, per-peer quota and global memory budget have been checked.

Every connection starts with `HELLO`, version negotiation, feature bits, fresh nonces and the peer-policy epoch. Authentication frames cannot be confused with message frames.

## Message envelope

The normative model should be represented in Core and serialised to deterministic CBOR:

```text
Envelope {
  protocol_major       uint
  protocol_minor       uint
  message_id           128-bit random
  conversation_id      128-bit random
  sender_peer_id       PeerId
  recipient_peer_id    PeerId
  sender_sequence      uint64
  actor                ActorAssertion
  message_type         enum
  created_at           timestamp label
  expires_at           optional timestamp label
  reply_to             optional MessageId
  body                  bounded UTF-8 text or typed payload
  references            bounded array<TypedReference>
  required_features     bit set
}
```

`sender_sequence` is monotonic per sender identity and conversation. It helps detect replay and gaps, but a remote clock or sequence never controls local ordering. The receiver assigns its own durable append sequence.

Actor assertions are structured values:

- `operator`: created through local operator UI, optionally carrying a local-presence assertion.
- `harness`: includes harness ID and proves the message came through that harness's scoped local token.
- `service`: reserved for narrow system-generated receipts and notices.

A scoped harness may assert only itself. It cannot send as the operator, another harness or an arbitrary process name. The receiving UI labels assertions as remote claims authenticated by the peer Foreman.

## Message types

Version 1 types:

- `note`: human-readable information.
- `task_request`: a request that can become a local, untrusted Ask Harness item.
- `audit_request`: a structured request for review, still requiring local policy.
- `reply`: response to another message.
- `status`: progress information without authority.
- `receipt`: protocol-generated delivered, read, declined or expired status.
- `repository_handoff`: bounded repository, branch, commit and worktree references; no file transfer.
- `operator_action_request`: asks the local operator to perform an action but cannot perform it.

Message type controls parsing, presentation and policy. It never grants authority. Sender-supplied priority is a display hint capped at Normal; only local validation can create a High or Critical security event.

## Local policy

Each peer starts at **Receive only**. Policy is local, sealed with settings and changed only through a Presence Lock-protected UI.

Peer identities, revocation state and policy epochs form a Guardian-sealed registry with atomic updates and rollback detection. Absence is treated as first run only when no prior initialisation evidence exists. If the established registry is deleted, corrupt or rolled back, the listener and automatic routing fail closed while recovery guidance remains available.

Messenger policy should integrate with Universal Trust Settings rather than create a parallel authority system. Universal settings provide the installation-wide ceiling; peer, message-type and target-harness rules may narrow that ceiling but never expand it. A local harness's existing trust policy is checked again before routing.

Recommended peer modes:

- **Blocked:** reject connections and queued input immediately.
- **Paused:** retain the peer but do not connect or deliver.
- **Receive only:** store and display acceptable messages; do not route to a harness.
- **Ask before routing:** prompt the operator before creating an Ask Harness item.
- **Unattended routing:** route only explicitly allowed message types to explicitly allowed local harnesses.

Fine-grained permissions:

- accept notes;
- accept task or audit requests;
- allow targeting a named local harness;
- allow repository references;
- send read receipts;
- notify while locked or in game mode;
- per-peer and per-harness daily and burst limits.

“Unattended” means unattended delivery into an untrusted inbox or Ask Harness request. It never means unattended tool execution or local approval.

## Durable mailbox and audit

Use a dedicated mailbox store, not the Vault and not the security event log.

- Encrypt each inbox and outbox record with AES-256-GCM using a mailbox-specific key, a fresh 96-bit cryptographically random nonce and an explicit key version. A nonce must never repeat under a key.
- Protect the mailbox key through the same platform abstraction as identity storage, but use independent key material.
- Include record identity, direction, peer ID, conversation ID and schema version as authenticated associated data.
- Use transactional writes and explicit schema migrations.
- Keep durable deduplication keys, highest contiguous sequence, bounded gap sets and terminal delivery states. Authenticate replay state and update it in the same transaction as inbox materialisation; missing or invalid established replay state pauses that peer rather than resetting its counters.
- Offer configurable retention, archive and deletion. Deletion is local and cannot recall a message from a peer.

Security telemetry records only bounded metadata: local sequence, message ID, peer ID, type, byte count, a ciphertext digest or domain-separated keyed audit digest, policy decision and delivery/approval state. It must not include the body, a plaintext body digest, prompt, secret-looking references or unbounded remote text.

The event log's local `Sequence` remains temporal truth. Remote timestamps are displayed with an “according to sender” label when materially different.

## Delivery state machine

Sender states:

```text
Draft -> Queued -> Sending -> Delivered -> [Read | Declined]
                   |    |          |
                   |    +-> Retry -+
                   +------> Failed
Queued/Sending ---------------------> Expired
```

Rules:

- Persist the complete outbox record before attempting a connection.
- Receiver validates, deduplicates and durably commits before sending `DELIVERED`.
- A duplicate returns the stored receipt and does not produce another UI or Ask Harness item.
- Retry with bounded exponential backoff and jitter.
- Cap queued messages and bytes per peer, local actor and installation.
- Reserve capacity for local security evidence; messenger traffic cannot consume or evict it.
- Treat disk-full, key-store failure and corrupt-state conditions as visible degraded states, not successful delivery.
- Expiry is a sender request evaluated against local policy and clock uncertainty; it is not a substitute for replay protection.

Version 1 sender-retained delivery means the sender must come online at the same time as the receiver. This is an acceptable MVP limitation and avoids prematurely operating a trusted relay.

## Performance and availability targets

Measure these on the supported low-end Windows test machine as well as a development workstation:

- queue a locally valid message and return its stable ID within 100 ms at p95, excluding first-time Presence Lock interaction;
- deliver and durably acknowledge a small message within 500 ms at p95 when an authenticated LAN connection is already available;
- keep UI and local safety-event processing responsive during peer reconnect storms and full messenger queues;
- bound handshake, frame-read, acknowledgement and idle timeouts independently so one stalled peer cannot occupy a worker forever;
- use per-peer connection and queue isolation so one slow or malicious peer does not head-of-line block another;
- expose queue age, retry reason and last authenticated contact without polling or logging message content.

These are engineering targets, not delivery claims. Phase 1 establishes repeatable benchmarks before a release threshold is fixed.

## Ask Harness integration

Add a new request kind, `remote_foreman_mail`, rather than presenting remote messages as ordinary local harness mail.

The adapter must:

1. Load the already validated message from the local encrypted inbox by ID.
2. Check the current peer and routing policy again at delivery time.
3. Build a local system wrapper stating that the content is untrusted remote evidence and cannot authorise execution, browsing, file access or secrets.
4. Preserve the peer, asserted actor, message type and local message ID as structured metadata.
5. Redact and cap display text using the local rules.
6. Route only to the exact locally allowed harness.
7. Send replies through the scoped local Messenger API so the harness can assert only itself.

Do not insert the remote `system_prompt` into a local system role. There is no network envelope field with that meaning.

## Local API and MCP tools

Initial read/send tools:

- `list_foreman_peers`: returns peer IDs, display names, coarse state and locally permitted capabilities.
- `send_foreman_message`: accepts peer ID, optional target harness, type, body and typed references.
- `list_foreman_messages`: lists messages visible to the authenticated local principal.
- `reply_foreman_message`: replies to an accessible message.
- `get_foreman_message_status`: returns durable delivery state.

Rules:

- A harness-scoped token can send only as that harness and see only policy-permitted conversations.
- MCP does not expose “send as operator”. The raw local operator token proves a local client role, not human presence. Operator-authored messages use the desktop UI and local app service; any future automation requires a separately named, explicitly granted capability.
- Pairing, key rotation, trust elevation, firewall changes and unpairing remain UI plus Presence Lock operations.
- Tools operate on local stores and queues, never directly on sockets.
- Inputs use strict schemas, bounded collections and typed repository references.
- Every mutation returns a stable operation or message ID for retry and audit.

## Messenger user experience and QOL

Add a Messenger page with:

- peer cards showing name, Peer ID suffix, connection state, trust mode, key protection class and last successful authentication;
- an inbox/outbox conversation view with delivery and local-approval state;
- a pairing wizard with QR/deep-link import, matching-code confirmation and full fingerprints;
- clear “remote request — not local approval” treatment;
- separate claimed actor, authenticated peer and local routing labels;
- one-click pause and block, with Presence Lock for destructive or trust-elevating changes;
- per-peer notification, game-mode and locked-session behaviour;
- searchable local history without sending search terms or indexes to a peer;
- copyable support metadata that excludes bodies and secrets;
- actionable failures such as “peer offline”, “identity changed”, “mailbox locked” and “policy declined”.

The complete pairing and messaging flow must be keyboard operable, expose useful automation names to screen readers, avoid colour-only trust signalling and offer a reduced-motion path for connection and delivery indicators.

Useful later additions include optional private-LAN discovery, contact aliases, archived conversations, resend/cancel while queued, and a “why was this delivered?” policy explanation.

## Future untrusted relay

A relay is a separate phase and changes the cryptographic requirement. TLS to a relay is not end-to-end protection between Foreman peers.

For relay delivery:

- retain the same peer identities and local authorisation model;
- encrypt payloads at the application layer using an audited HPKE implementation;
- sign or authenticate a canonical COSE/CBOR envelope binding sender, recipient, version, message ID and ciphertext;
- let the relay see only the minimum routing and anti-abuse metadata, documenting that metadata leakage remains;
- use short-lived relay credentials unrelated to MCP or Vault material;
- make relay storage quotas, deletion, abuse handling and availability explicit.

HPKE provides message encryption but not Signal-style post-compromise security. Do not claim that property. A future ratchet or MLS-based group design should be a separately reviewed protocol using a maintained, audited library.

## Red-team and failure test matrix

Every security fix must test the invariant and sibling bypasses, not only the first named path.

### Identity and pairing

- stolen invitation used before and after intended pairing;
- invitation replay, pre-creation, expiry, race and rate-limit exhaustion;
- MITM presents two valid self-signed identities;
- operators confirm mismatched authentication strings;
- identity certificate renewal with same key versus unexpected key replacement;
- deleted, rolled-back or attacker-edited peer store;
- deleted or rolled-back replay store is treated as a fresh empty counter;
- blocked peer attempts TLS resumption and connection churn;
- DPAPI fallback key copied by another account and by the same account;
- two development instances accidentally reuse identity material.

### Protocol and parsing

- version downgrade and unknown mandatory feature;
- malformed, non-canonical, deeply nested or duplicate-key CBOR;
- zero, maximum and oversized frames, partial reads and stalled frames;
- decompression-bomb attempt when compression is disabled;
- mismatched sender or recipient Peer ID inside a valid TLS channel;
- forged operator, service or different-harness assertion;
- sequence replay, gap, rollback, wraparound and message-ID collision;
- duplicate after crash between durable commit and acknowledgement.

### Authorisation and prompt safety

- remote system-prompt injection and tool-use instruction;
- a peer requests Vault, CU, ADB, browser, settings or Guardian access;
- remote “operator approved” claim arrives while the local session is locked;
- disallowed target harness and target alias confusion;
- repository reference with path traversal, URL userinfo or malicious scheme;
- repository or URL reference is fetched, opened or resolved without a separate local action;
- sender-supplied Critical priority and alert flood;
- peer policy changes between receipt and local routing.

### Reliability and availability

- receiver disk fills before commit, during commit and before receipt;
- key store is unavailable, mailbox record is corrupt, or migration fails;
- abrupt process termination at every state transition;
- clock moves backwards or forwards by days;
- peer floods frames, connections, conversations and receipts;
- one peer's queue fills while other peers and local security surfaces remain functional;
- network switches between LAN, VPN, IPv4 and IPv6 mid-delivery;
- public-network firewall profile is activated after pairing.

### Privacy and audit

- secrets and message bodies do not enter event logs, crash reports or notifications;
- local deletion does not falsely claim remote recall;
- locked-screen and game-mode notifications reveal only configured metadata;
- support export contains hashes and state but no message plaintext.

## Acceptance criteria for the MVP

The MVP is complete only when:

1. Two clean Foreman installations can pair with matching-code confirmation and pinned independent identities.
2. A message survives sender restart, network loss and receiver restart without duplication.
3. A receipt is issued only after the receiver's encrypted durable commit.
4. An authenticated malicious peer cannot directly trigger any local privileged operation.
5. A remote harness cannot impersonate the remote operator, another harness or a local principal.
6. Blocking a peer prevents new and resumed connections immediately.
7. Windows 10 TLS 1.2 and Windows 11 TLS 1.3 paths pass the same protocol and abuse suite.
8. Mailbox, key-store, firewall and audit failures are visible and fail closed where trust is required.
9. Security telemetry contains no message body or unbounded sender-controlled text.
10. Fuzzing and property tests cover framing, canonical decoding, replay, policy and state transitions.
11. A fresh independent red-team pass finds no path from remote input to local execution or approval.
12. Documentation states the same-user and direct-delivery limitations without overstating end-to-end or hardware security.
13. Deleting or rolling back an initialised peer registry or replay store disables affected peer delivery and produces a recovery state; it never restores default trust or resets replay protection.
14. No MCP credential, including the raw local operator token, can originate a message asserted as human-authored.

## Delivery roadmap

### Phase 0 — ADR, threat model and crypto spike

Estimated outcome: design is reviewable before feature code.

- Adopt the invariants and non-goals in an architecture decision record.
- Prototype CNG/TPM and DPAPI fallback identity storage on supported Windows versions.
- Prove mutual `SslStream` authentication, pinned SPKI validation, ALPN and TLS negotiation on Windows 10 and 11.
- Select and fuzz a maintained deterministic-CBOR library.
- Define protocol test vectors and the peer-policy schema.
- Hold a security review with explicit go/no-go on identity storage and TLS 1.2 configuration.

Exit gate: no unresolved custom-crypto requirement; reproducible handshake and envelope test vectors exist.

### Phase 1 — Protocol core and two-instance simulator

- Implement identifiers, envelopes, typed references and canonical codec.
- Implement inbox/outbox state machines, idempotency and durable replay windows behind in-memory test stores.
- Build a deterministic two-peer loopback simulator with loss, duplication, reorder, crash and clock controls.
- Add property tests and parser fuzz targets before real network exposure.

Exit gate: the simulator proves at-least-once transport with exactly-once local materialisation.

### Phase 2 — Identity, pairing and direct transport

- Implement protected identity storage and posture reporting.
- Implement invitations, provisional handshake, transcript authentication string and two-sided confirmation.
- Implement the dedicated listener/connector, mTLS pinning, application `HELLO`, revocation checks and bounded framing.
- Add interface selection and private-profile firewall management.

Exit gate: two machines pair and authenticate; MITM, replay, key-change and resumed-revoked-peer tests fail closed.

### Phase 3 — Durable messenger and safe harness bridge

- Implement encrypted mailbox storage, migrations, quotas, retry and receipts.
- Add Messenger UI, conversations, peer policies, pause/block and failure explanations.
- Add scoped local Messenger APIs and MCP tools.
- Add `remote_foreman_mail` wrapping and per-peer/per-harness routing policy.
- Audit logging uses metadata only.

Exit gate: all MVP acceptance criteria except the independent review pass are green.

### Phase 4 — Hardening and independent red team

- Run parser fuzzing, state-machine property tests and network chaos tests continuously.
- Test Windows 10/11, locked/unlocked sessions, game mode, upgrade, downgrade and corrupt-state recovery.
- Review key ACLs, dumps, telemetry, notification privacy, URI handling and firewall lifecycle.
- Have a reviewer attack security properties rather than named fixes and document sibling paths considered.

Exit gate: no open P0/P1 issue and every security property has an adversarial test.

### Phase 5 — Direct-mode QOL

- Add opt-in private-LAN discovery.
- Improve endpoint roaming, contact import/export without private keys, search and archives.
- Add richer repository handoff references and policy explanations.
- Measure connection setup, wake, queue and delivery latency.

### Phase 6 — Optional relay

- Write a separate relay threat model and privacy statement.
- Select audited HPKE and COSE/CBOR libraries and publish vectors.
- Implement opaque store-and-forward, quotas, abuse controls and application-layer encrypted receipts.
- Prove that relay compromise cannot read or alter message content undetected.

### Phase 7 — Attachments and group messaging, if justified

- Attachments start as explicit offers with hashes, size limits, quarantine, content scanning and never-auto-open behaviour.
- Group messaging or post-compromise security requires a separately reviewed ratchet or MLS design.
- Neither is allowed to silently expand the authority of remote messages.

## Suggested work packages

1. **Protocol ADR and test vectors** — owner: Core/security.
2. **Identity provider abstraction** — owner: Windows security.
3. **Pairing state machine** — owner: App plus security review.
4. **Transport and frame parser** — owner: networking.
5. **Encrypted mailbox and migrations** — owner: storage.
6. **Policy engine and Ask Harness adapter** — owner: Core/MCP.
7. **Messenger and pairing UI** — owner: App/UX.
8. **Fuzz, chaos and adversarial suite** — owner: test/security, independent of feature authors where practical.
9. **Operations documentation** — owner: release/security.

Each package should ship with an invariant statement, normal-path tests, bypass tests, upgrade and first-run behaviour, degraded-dependency behaviour and operator-facing diagnostics.

## Open decisions to resolve in Phase 0

- Which maintained CBOR implementation meets deterministic encoding and resource-limit requirements on .NET 10?
- Can the chosen Windows key provider retain one P-256 identity key across certificate renewal on the complete target hardware matrix?
- Should TLS session resumption be disabled in v1 or can local revocation and policy checks be guaranteed before application data?
- What default mailbox retention and per-peer byte quotas balance QOL with privacy?
- Is manual endpoint entry enough for MVP, or is private-LAN discovery required for the first usable release?
- Should read receipts default off for privacy, even when delivery receipts remain mandatory?

These decisions do not weaken the invariants above.

## Standards and implementation references

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9325 — Recommendations for secure use of TLS](https://www.rfc-editor.org/rfc/rfc9325)
- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [RFC 9180 — HPKE](https://www.rfc-editor.org/rfc/rfc9180)
- [RFC 9420 — Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420)
- [Microsoft: `SslStream` authentication troubleshooting](https://learn.microsoft.com/en-us/dotnet/core/extensions/sslstream-troubleshooting)
- [Microsoft: TLS protocol support in Schannel](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)

## Recommended next action

Approve Phase 0 only. Do not start the messenger UI or MCP surface until the identity-storage spike, pinned mutual-TLS handshake, deterministic envelope vectors and security-property test plan have passed review. That keeps the riskiest decisions small, reversible and independently testable before they become a user-facing protocol.
