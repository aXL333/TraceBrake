# Automation Declaration v1.0 conformance test vectors

CC0 1.0, same as [the specification](../automation-declaration-v1.md). Copy them, ship them, modify them. No
attribution required.

```
python validate.py      # run every vector against the reference validator
python generate.py      # regenerate the vectors and index.json
```

Current state: **41 vectors, 41 passing.**

## What is here

| File | Purpose |
|---|---|
| `index.json` | The manifest. One entry per vector: expectation, spec section, rationale, and environment facts. |
| `<vector-id>.json` | A declaration document. Nothing else. |
| `validate.py` | Reference implementation of the mechanically checkable rules, plus the runner. |
| `generate.py` | Produces the vectors. Bounds cases are generated rather than hand-typed so they stay exact. |

## The design decision worth understanding

**A vector document contains only the declaration.** Everything a consumer would learn from its *environment*
lives in `index.json`, in the vector's `env` object:

```json
"env": { "signatureValid": false, "hashesMatch": true, "scope": "machine", "observedBehaviours": [] }
```

This is not a convenience. Spec section 4.3 forbids a document from asserting its own validity, and there is
deliberately no `signed` or `verified` field in the schema. A vector that carried `"signatureValid": false` inside
the document would be testing a format that does not exist, and would quietly teach implementers the wrong shape.
One vector, `invalid-self-asserting-signed-field`, exists precisely to reject a document that tries it.

`scope` is `machine`, `user` or `none`. `observedBehaviours` supports the runtime under-declaration case, which
cannot be judged from a document alone.

## Expectations

| Value | Meaning |
|---|---|
| `VALID` | The document is valid. A consumer may use it for explanation only (5.2.8). |
| `INVALID` | The consumer must treat the declaration as **absent** (5.4). Not as weakly credible. |
| `VALID_BUT_UNCREDITED` | Structurally valid, but published per-user, so worth no more than absence (5.2.5). |
| `ABSENT` | No declaration. Consumer behaviour must be identical to the no-format case (5.2.3). |

## Coverage

Valid baselines, including one sitting exactly on every bound, since bounds are inclusive and off-by-one is the
likeliest implementation error.

Identity failures: broken signature, component hash not matching disk, and a document asserting its own validity.

Closed-schema failures: each prohibited field from section 5.3 individually, an unknown field, an `x-` prefixed
extension, a field carrying a CLSID and library path, an inventory of observed processes, and a field whose name is
legal but whose semantics express a request.

Vocabulary failures: unknown behaviour token, unknown scope, over-long `purpose`, `purpose` naming a port, and a
behaviour referencing a component absent from `components`.

Working-set failures: 33 roots, an entry carrying an `action` verb, and an unknown `reason`.

Bounds and lifetime: a document over 64 KiB, expired, issued in the future, unknown `specVersion`.

Content and privacy: control character, bidirectional override, a user-name-bearing path, a security identifier.

Runtime: a declarant observed performing a behaviour it did not declare.

Consumer behaviour: per-user scope, absence, hostile-but-legal string content, and a duplicate `declarantId`
resolved by newest `issuedUtc`.

## What the vectors cannot test

Two requirements are structural properties of a consumer, not of any document, and no vector can establish them:

- **5.2.1**, that no code path exists from declaration parsing to a scanning, scoring or blocking decision. This is
  the requirement the whole format's safety rests on, and it is checkable by inspection.
- **5.2.3**, that absence is not treated as a negative signal. Assert behaviour byte-identical to a build with no
  declaration support compiled in.

Two more need human judgement. The 5.3 catch-all against fields whose *semantics* express a request cannot be
caught by name matching, though in practice the closed-schema rule catches most instances because such a field is
also unknown. And 4.4 rule 3, forbidding operational detail in `purpose`, is only partly automatable: the reference
validator flags an obvious port pattern and nothing more.

## Adding a vector

Add a `vector(...)` call in `generate.py`, run it, run `validate.py`. If the new vector fails, either the vector is
wrong or the validator is. If the specification and `validate.py` disagree, **the specification wins** and the
validator is the thing to fix.
