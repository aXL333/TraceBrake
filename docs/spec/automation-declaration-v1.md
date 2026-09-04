# The Automation Declaration Format, Version 1.0

**Status:** Draft. Not yet implemented. Breaking changes expected before 1.0 final.
**Editor:** Blue Heeler Software · xredux@protonmail.com
**Licence:** This specification is published under CC0 1.0. It may be read, implemented, copied and modified by
anyone, including proprietary vendors, without attribution or licence obligation. The reference implementation is
licensed separately.

Rationale for automation provenance, and the evidence motivating it, is in
[Automation Provenance](../whitepaper-automation-provenance.md). This document is the normative format
specification.

---

## 1. Scope

An **Automation Declaration** is a signed document in which software that supervises automated execution states its
own identity, the behaviours it performs that resemble malicious activity, the automation sessions it supervises,
and the filesystem locations where its supervised work produces high write churn.

**The declaration confers nothing.** It is not a request, a permission, an exemption, an allowlist entry, or an
assertion of trustworthiness. It is a statement of fact by a party with an interest in the outcome, and it is
useful only to the extent that a reader independently verifies it.

This specification defines the document format, the rules that make a declaration valid or invalid, and separate
conformance requirements for the software that publishes a declaration and for any software that reads one.

### 1.1 Non-scope

This specification does not define an isolation mechanism, a container, a scanning interface, a query protocol, an
enforcement point, or any means by which a declarant may influence a security product's decisions. Proposals in
those directions are out of scope by construction and are addressed in Section 5.

---

## 2. Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to
be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

**Declarant.** Software that publishes an Automation Declaration describing itself.

**Consumer.** Any software that reads an Automation Declaration. In practice this is expected to be an endpoint
security product, a support-diagnostic tool, or an operator-facing user interface.

**Supervised session.** A bounded period of automated execution that the declarant observes and can attribute
processes, command lines and file writes to.

**Machine-generated execution.** A process, command line or file write initiated by software acting on a human
user's behalf, rather than by a human directly at an input device.

**Declared behaviour.** An entry from the closed vocabulary in Section 4.4, naming something the declarant does
that a behavioural detector may reasonably find suspicious.

---

## 3. Document location and discovery

A declaration is a UTF-8 encoded JSON document named `automation-declaration.json`, accompanied by a detached
signature file `automation-declaration.jws`.

Declarants SHOULD publish the declaration inside their own installation directory and register its absolute path in
a vendor-owned location. This specification does not mandate a discovery mechanism in version 1.0, because a
registry namespace that is writable by unprivileged code is worse than no discovery at all. Implementers evaluating
a discovery mechanism SHOULD first evaluate ISO/IEC 19770-2 SWID tags and IETF CoSWID as the carrier, since an
automation-provenance profile of an existing standard inherits its lifecycle, tooling and institutional
familiarity.

Where a registration key is used:

- It MUST be created with an access control list set explicitly at creation, granting write access to
  administrators only and read access to all users. It MUST NOT rely on inherited permissions.
- It MUST be written by an installer running with administrative privilege, and MUST NOT be written by the
  declarant at runtime.
- On uninstall, the registration MUST be removed **before** the declaration file and the declarant's binaries. An
  interrupted uninstall must leave files without a registration, never a registration pointing at a path that no
  longer exists and that an attacker could subsequently create.

---

## 4. Document structure

```json
{
  "specVersion": "1.0",
  "declarantId": "software.blueheeler.tracebrake",
  "issuedUtc": "2026-09-05T14:22:00Z",
  "expiresUtc": "2027-09-05T14:22:00Z",
  "product": { "name": "TraceBrake", "version": "0.1.0", "vendor": "Blue Heeler Software" },
  "components": [
    { "path": "TraceBrake.exe", "sha256": "..." },
    { "path": "sidecar/Foreman.EtwSidecar.exe", "sha256": "..." }
  ],
  "declaredBehaviours": [
    { "token": "process.enumerate", "scope": "system-wide", "components": ["TraceBrake.exe"],
      "purpose": "Builds the process tree used to attribute activity to a supervised session." },
    { "token": "process.terminate", "scope": "supervised-subjects-only", "components": ["TraceBrake.exe"],
      "purpose": "Operator-initiated termination of a supervised agent process." }
  ],
  "supervisedSubjects": [
    { "kind": "coding-agent", "identifier": "claude-code", "bindingMethod": "process-ancestry" }
  ],
  "workingSet": [
    { "root": "%USERPROFILE%/src", "reason": "build-output", "churn": "high", "source": "user-configured" }
  ],
  "contactUri": "https://github.com/aXL333/Foreman/issues"
}
```

### 4.1 `declarantId`

A reverse-DNS identifier. It MUST NOT be derived from a file path or a display name, both of which are attacker
controlled in the general case. Where two valid declarations present the same `declarantId`, a consumer MUST resolve
in favour of the newest `issuedUtc` and MUST treat the loser as stale, and SHOULD report the collision.

### 4.2 `components`

Each entry binds a file to a SHA-256 hash. Identity in this format rests on the signing key and on these hashes. A
consumer MUST NOT treat a matching Authenticode subject as identifying the declarant, because signing programmes for
open-source projects issue certificates to the programme rather than to the project, so the subject is shared across
unrelated products.

### 4.3 Signature

The declaration MUST be signed with a key controlled by the declarant, published as a detached JWS.

A consumer MUST verify the signature, and MUST verify each `components` hash against the file on disk, **at read
time**. A consumer MUST NOT trust any field inside the document that asserts its own validity. There is deliberately
no `signed`, `verified` or `trusted` field in this schema, and a document containing one is invalid under
Section 5.3.

### 4.4 `declaredBehaviours`

Each entry names a `token` from the closed vocabulary below, a `scope` from the closed enumeration below, the
`components` that perform it, and a bounded free-text `purpose`.

The version 1.0 vocabulary is:

| Area | Tokens |
|---|---|
| `process` | `enumerate`, `inspect-command-line`, `subscribe-creation`, `terminate`, `suspend`, `read-memory` |
| `filesystem` | `watch`, `write-outside-install`, `read-user-documents`, `plant-canary` |
| `registry` | `write-run-key`, `write-outside-own-hive`, `read-security-state` |
| `network` | `listen-loopback`, `listen-external`, `connect-outbound` |
| `privilege` | `request-elevation`, `run-elevated-helper`, `install-service` |
| `script` | `observe-content` |
| `telemetry` | `consume-os-event-log`, `consume-etw`, `read-security-product-state` |

`scope` is one of `self-only`, `supervised-subjects-only`, `working-set-only`, `system-wide`.

Three rules govern this section, and each exists to close a specific abuse:

1. **Unknown tokens invalidate.** A consumer encountering a token outside the vocabulary for the declared
   `specVersion` MUST treat the entire declaration as invalid. It MUST NOT ignore the unknown entry and accept the
   rest. Graceful degradation here would make novel tokens a laundering channel.
2. **Under-declaration invalidates.** A declarant MUST declare every behaviour it performs that has a token in the
   vocabulary. A consumer that observes a declarant performing an undeclared behaviour MUST treat the declaration as
   invalid. Minimising is therefore worse than over-declaring, which is the intended incentive.
3. **No operational detail.** A `purpose` string MUST NOT name a port, an authentication scheme, a service name, a
   registry key path, a named pipe, a command line, or a credential location. Publishing operational detail assists
   an attacker considerably more than it assists a consumer. `purpose` MUST be at most 200 characters.

### 4.5 `supervisedSubjects`

Identifies the automation this declarant supervises and how a process is bound to a session. Where a
platform-native agent identity exists, `identifier` SHOULD carry it rather than a parallel identifier invented by the
declarant.

This section MUST NOT contain a list of processes, applications or users being monitored on the local machine. It
describes what kind of automation the declarant supervises, not an inventory of what it has observed.

### 4.6 `workingSet`

Filesystem roots where supervised work produces high write churn or short-lived intermediate binaries.

**This section is purely descriptive and has no verbs.** `reason` is drawn from a closed enumeration
(`build-output`, `package-cache`, `intermediate-artifacts`, `snapshot-store`), `churn` from `low` / `medium` /
`high`, and `source` from `install` / `user-configured` / `derived` so that a consumer can independently verify any
entry claimed to originate from installation. At most 32 roots MAY be declared.

An entry in `workingSet` is a statement that churn occurs at a path. It is **not** a request that anything be
excluded, skipped, deprioritised or treated differently, and a consumer that implements it as one is non-conforming
under Section 5.2.

---

## 5. Conformance

This section is normative and is the core of the specification. An implementation that satisfies Sections 4 and 5.1
is a **conforming declarant**. An implementation that satisfies Section 5.2 is a **conforming consumer**. The two
are independent: a conforming consumer need not publish declarations, and a conforming declarant need not read them.

### 5.1 Declarant conformance

A conforming declarant:

1. MUST publish a declaration that validates against Sections 3 and 4.
2. MUST declare every behaviour it performs for which a vocabulary token exists (Section 4.4, rule 2).
3. MUST sign the declaration with a key it controls, and MUST keep `components` hashes accurate across updates.
4. MUST NOT register with Windows Security Center in any category, MUST NOT ship an Early Launch Anti-Malware
   driver, MUST NOT register as an AMSI provider, and MUST NOT install a filesystem minifilter. Publishing a
   declaration is not a step toward any of these, and a declarant that does any of them is outside the class this
   specification describes. On current Windows client releases, registering a non-Microsoft antivirus with Security
   Center causes Microsoft Defender Antivirus to be disabled, so such a registration would reduce the protection of
   the machine the declarant claims to be helping.
5. MUST NOT write, modify or delete any configuration belonging to another vendor's security product. In particular
   it MUST NOT programmatically add, modify or remove a scan exclusion in any product, at any time, for any reason,
   including in response to an operator request. It MAY render a command for the operator to run themselves.
6. MUST NOT enforce. It MUST NOT block, quarantine, roll back, or deny any operation on the basis of anything in a
   declaration, its own or anyone else's.
7. MUST NOT re-assert its own persistence more than once after observing external removal. On detecting that its own
   run-at-login entry has been removed by another party, a declarant MAY restore it once, and MUST then stop and
   report to the operator. Repeated self-restoration is indistinguishable from malicious persistence.
8. MUST NOT include personally identifying information anywhere in a declaration. This includes user names, machine
   names, security identifiers, email addresses, document paths, and repository or project names not owned by the
   declarant.
9. SHOULD compare its own observed behaviour against its published declaration and report divergence to the
   operator.

### 5.2 Consumer conformance

A conforming consumer:

1. **MUST NOT use a declaration, or its absence, as an input to any detection, scanning, blocking, quarantine,
   scoring, prioritisation or verdict decision.** This is the single requirement on which the safety of the entire
   format rests. A declaration may inform what a human is *told*. It may never inform what a machine *does*.
2. MUST NOT treat the presence of a declaration as evidence of trustworthiness, benignity, or good intent.
3. **MUST NOT treat the absence of a declaration as a negative signal.** Penalising software that does not publish
   one would make the format coercive, and would disadvantage exactly the small and open-source developers it exists
   to serve.
4. MUST verify the signature and every `components` hash against the files on disk before reading any other field,
   and MUST treat an unsigned, mismatched, malformed or expired declaration as **absent**, never as weakly credible.
5. MUST treat a declaration published in a per-user scope as an assertion by whatever code runs as that user, which
   includes malware running with that user's credentials. Per-user declarations are trivially forgeable, and this
   specification defines them as assertions rather than pretending otherwise.
6. MUST treat every string field as untrusted input. `purpose`, `workingSet.root` and `product.name` are attacker
   controlled in the general case and MUST be sanitised before rendering, and MUST NOT be interpolated into a path,
   a command, a query or a rule.
7. MUST NOT resolve or fetch `contactUri` automatically. It exists for a human to open deliberately.
8. MAY use a valid declaration to explain to a human why an observed process chain looks the way it does, to
   attribute an interdiction to a supervised session in a support workflow, or to enrich a diagnostic report.

### 5.3 Prohibited fields

The schema is **closed**. A declaration containing any field not defined in Section 4 is invalid, and a consumer
MUST reject it rather than ignoring the unknown field.

Beyond that general rule, the following are permanently prohibited and MUST NOT be added to this schema in any
future version. A version of this specification that introduces any of them is not a successor to this
specification:

- `action`, `allow`, `allowlist`, `exclude`, `exclusion`, `exempt`, `exemption`, `trust`, `trusted`, `suppress`,
  `suppression`, `whitelist`, `bypass`, `skip`, `ignore`, `priority`, `severity`, `confidence`, `verdict`,
  `signed`, `verified`, `approved`.
- Any field, by any name, whose semantics express a request, instruction, preference, expectation or entitlement
  regarding a consumer's behaviour.
- Any field carrying executable content, a CLSID, a library path, a command line, or a URI that a consumer is
  expected to resolve automatically.
- Any field enumerating processes, users, applications or files observed on the local machine.

The reason is stated plainly so that a future contributor cannot mistake it for style. **A format in which software
can declare itself benign and thereby receive different treatment is a self-service allowlist, and a self-service
allowlist is a malware primitive.** The absence of these fields is not an oversight to be corrected. It is the
property that makes the format safe to publish at all.

### 5.4 Validity

A declaration is **invalid** if any of the following hold. A consumer MUST treat an invalid declaration as absent.

- The signature does not verify, or any `components` hash does not match the file on disk.
- `specVersion` is unrecognised, or `issuedUtc` is in the future, or `expiresUtc` has passed.
- Any field is present that is not defined in Section 4, or any field in Section 5.3 is present.
- Any `declaredBehaviours.token` is outside the vocabulary for the declared `specVersion`.
- The declarant is observed performing a behaviour with a vocabulary token that it did not declare.
- Any bound in Section 4 is exceeded: more than 32 `workingSet` roots, a `purpose` longer than 200 characters, or a
  document larger than 64 KiB.

### 5.5 Extension policy

New behaviour tokens are the expected form of extension and require a new `specVersion`. Vendor-specific tokens,
private vocabularies and `x-` prefixed fields are **not permitted**, because a consumer cannot evaluate a token
whose meaning it does not know, and any mechanism that lets an unknown token pass validation reopens the laundering
channel that Section 4.4 rule 1 closes.

### 5.6 Conformance test vectors

An implementation claiming conformance SHOULD be validated against the published test vector set, which MUST
include, at minimum, one case for each of: a valid declaration; a declaration with a broken signature; a declaration
whose component hash does not match disk; a declaration containing an unknown behaviour token; a declaration
containing a prohibited field from Section 5.3; a declaration exceeding each bound in Section 5.4; and a declarant
observed performing an undeclared behaviour.

A consumer implementation SHOULD additionally be tested for the negative requirement in Section 5.2.1, by asserting
that no code path exists from declaration parsing to any scanning, scoring or blocking decision. This is a
structural property and is testable by inspection.

---

## 6. Security considerations

**The format is a confession, not a credential.** Every safety property follows from the fact that a declaration
grants nothing. Section 5.2.1 and Section 5.3 are the load-bearing requirements. If a consumer implementation
violates 5.2.1, or a future version of this schema violates 5.3, the format becomes a mechanism by which malware
declares itself benign and receives different treatment, at which point publishing it was a mistake.

**Forgery is expected and definitionally accounted for.** Anything running with a user's credentials can write a
per-user declaration, and anything running with administrative privilege can write a machine-scope one and register
it. This is why Section 5.2.5 defines per-user declarations as assertions, why Section 5.2.2 forbids treating
presence as evidence of good intent, and why the format grants nothing that would make forging one worthwhile.

**The declaration is a reconnaissance surface.** It tells a reader what supervisory software is present and what it
does, which is information an attacker performing security software discovery would value. This is the reason
Section 4.4 rule 3 forbids operational detail, Section 4.5 forbids monitored-entity inventories, and Section 5.3
forbids fields carrying library paths or CLSIDs. The residual disclosure is judged acceptable because the same facts
are obtainable by an attacker who is already running on the machine, and because the declarant's product name and
presence are not secret.

**Under-declaration is the attack the incentives must handle.** A declarant that omits its least defensible
behaviour gains nothing, because Section 4.4 rule 2 makes the whole declaration invalid the moment that behaviour is
observed, and an invalid declaration is treated as absent. Over-declaring costs nothing. The incentive gradient
points toward honesty by construction rather than by good faith.

**Dangling registrations are a plant primitive.** The uninstall ordering requirement in Section 3 exists because a
registration surviving its target creates a path an attacker can create and populate. Ordering is normative for that
reason.

---

## 7. Privacy considerations

A declaration describes software, not people. Section 5.1.8 prohibits personally identifying information, and
Section 4.5 prohibits inventories of observed entities. `workingSet` roots are the one field with meaningful privacy
exposure, since a path can disclose a project name or an employer. Declarants SHOULD use environment-variable forms
such as `%USERPROFILE%/src` rather than absolute paths, and MUST NOT declare roots outside their supervised scope.

---

## 8. Versioning

Three version axes are tracked separately and MUST NOT be conflated: the discovery mechanism version, `specVersion`
(this document and its vocabulary), and `product.version`. A change to any one of them does not imply a change to
the others.

---

## Appendix A. Rationale for what is absent

Readers familiar with adjacent formats will notice several things this specification does not have, and each
omission is deliberate.

There is **no trust or reputation field**, because the format does not carry trust. There is **no exclusion or
exception mechanism**, for the reason given in Section 5.3. There is **no query or negotiation protocol**, because a
"did you block this?" interface is an evasion oracle and because the format's value does not depend on one. There
is **no capability grant**, **no privilege request**, and **no enforcement point**.

What a security vendor would find most useful from this project is not in this document at all, because it flows the
other way: a machine-readable record emitted when an enforcement layer interdicts an operation or overrides an
operator-authored exclusion. That request is made in the whitepaper. It reduces no detection capability and grants
no third party influence over a verdict, and it would have prevented the incident that motivated this work.
