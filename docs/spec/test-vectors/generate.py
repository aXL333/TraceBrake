#!/usr/bin/env python3
"""Generate the Automation Declaration v1.0 conformance test vectors.

CC0 1.0. Run from this directory: python generate.py

Every vector is a pure declaration document. Facts a consumer would learn from its
ENVIRONMENT rather than from the document (whether the signature verified, whether
component hashes matched disk, what behaviour was actually observed, what scope the
declaration was published in) live in index.json alongside the vector, never inside
the document. Putting them in the document would violate spec section 4.3, which
forbids a document asserting its own validity.
"""

import json
import io
import os

SPEC_VERSION = "1.0"
EVALUATION_TIME = "2026-09-05T12:00:00Z"

VALID_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def base(**overrides):
    """A minimal valid declaration. Overrides are shallow-merged; None deletes a key."""
    doc = {
        "specVersion": SPEC_VERSION,
        "declarantId": "software.example.supervisor",
        "issuedUtc": "2026-09-01T00:00:00Z",
        "expiresUtc": "2027-09-01T00:00:00Z",
        "product": {"name": "ExampleSupervisor", "version": "1.0.0", "vendor": "Example Software"},
        "components": [{"path": "ExampleSupervisor.exe", "sha256": VALID_SHA}],
        "declaredBehaviours": [
            {
                "token": "process.enumerate",
                "scope": "system-wide",
                "components": ["ExampleSupervisor.exe"],
                "purpose": "Builds the process tree used to attribute activity to a supervised session.",
            }
        ],
        "supervisedSubjects": [
            {"kind": "coding-agent", "identifier": "example-agent", "bindingMethod": "process-ancestry"}
        ],
        "contactUri": "https://example.invalid/issues",
    }
    for k, v in overrides.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


VECTORS = []


def vector(vid, section, expect, why, doc, env=None, notes=None):
    VECTORS.append({
        "id": vid,
        "specSection": section,
        "expect": expect,
        "why": why,
        "file": vid + ".json",
        "env": env or {"signatureValid": True, "hashesMatch": True, "scope": "machine", "observedBehaviours": []},
        "notes": notes,
        "_doc": doc,
    })


# ---------------------------------------------------------------- valid cases
vector("valid-minimal", "4", "VALID",
       "Minimum conforming document. Every other vector is a mutation of this one.",
       base())

vector("valid-no-working-set", "4.6", "VALID",
       "workingSet is optional. Its absence is not a defect.",
       base())

vector("valid-full", "4", "VALID",
       "Every optional section populated with in-bounds values.",
       base(
           components=[
               {"path": "ExampleSupervisor.exe", "sha256": VALID_SHA},
               {"path": "sidecar/Helper.exe", "sha256": VALID_SHA},
           ],
           declaredBehaviours=[
               {"token": "process.enumerate", "scope": "system-wide",
                "components": ["ExampleSupervisor.exe"],
                "purpose": "Builds the process tree used for session attribution."},
               {"token": "process.terminate", "scope": "supervised-subjects-only",
                "components": ["ExampleSupervisor.exe"],
                "purpose": "Operator-initiated termination of a supervised agent process."},
               {"token": "privilege.run-elevated-helper", "scope": "self-only",
                "components": ["sidecar/Helper.exe"],
                "purpose": "Reads event sources that require elevation."},
           ],
           workingSet=[
               {"root": "%USERPROFILE%/src", "reason": "build-output", "churn": "high", "source": "user-configured"},
               {"root": "%LOCALAPPDATA%/pkg-cache", "reason": "package-cache", "churn": "medium", "source": "install"},
           ],
       ))

vector("valid-at-bounds", "5.4", "VALID",
       "Exactly at every bound: 32 workingSet roots and a 200-character purpose. Bounds are inclusive.",
       base(
           declaredBehaviours=[{
               "token": "process.enumerate", "scope": "system-wide",
               "components": ["ExampleSupervisor.exe"],
               "purpose": "x" * 200,
           }],
           workingSet=[
               {"root": "%%USERPROFILE%%/w{}".format(i), "reason": "build-output",
                "churn": "low", "source": "derived"} for i in range(32)
           ],
       ))

# ------------------------------------------------- signature and identity (4.3)
vector("invalid-signature-broken", "4.3, 5.2.4", "INVALID",
       "Document is well formed but the detached signature does not verify. Treated as ABSENT, not as weakly credible.",
       base(), env={"signatureValid": False, "hashesMatch": True, "scope": "machine", "observedBehaviours": []})

vector("invalid-component-hash-mismatch", "4.3, 5.2.4", "INVALID",
       "Signature verifies but a components hash does not match the file on disk. The binary was replaced after signing.",
       base(), env={"signatureValid": True, "hashesMatch": False, "scope": "machine", "observedBehaviours": []})

vector("invalid-self-asserting-signed-field", "4.3, 5.3", "INVALID",
       "Carries its own validity claim. A consumer must never trust a field asserting the document is signed or verified.",
       base(signed=True, verified=True))

# ------------------------------------------------------- closed schema (5.3)
for field, value in [
    ("action", "exclude"),
    ("allow", ["%USERPROFILE%/src"]),
    ("exemption", {"paths": ["C:/build"]}),
    ("trust", "high"),
    ("suppress", ["ransomware-heuristics"]),
    ("verdict", "benign"),
    ("confidence", 0.99),
    ("whitelist", ["ExampleSupervisor.exe"]),
]:
    vector("invalid-prohibited-{}".format(field), "5.3", "INVALID",
           "Contains the prohibited field '{}'. Fields in the section 5.3 list may never appear, in any version.".format(field),
           base(**{field: value}))

vector("invalid-unknown-field", "5.3", "INVALID",
       "Contains a field not defined in section 4 and not on the prohibited list. The schema is closed, so unknown fields "
       "invalidate rather than being ignored.",
       base(vendorNotes="internal build 42"))

vector("invalid-x-prefixed-extension", "5.5", "INVALID",
       "Private or x- prefixed extensions are not permitted. Any mechanism letting an unknown key pass validation reopens "
       "the laundering channel that section 4.4 rule 1 closes.",
       base(**{"x-example-telemetry": {"enabled": True}}))

vector("invalid-executable-content", "5.3", "INVALID",
       "Carries a CLSID and a library path. A declaration must never name executable content a consumer could be induced to load.",
       base(provider={"clsid": "{00000000-0000-0000-0000-000000000000}", "inprocServer32": "C:/x/evil.dll"}))

vector("invalid-monitored-inventory", "4.5, 5.3", "INVALID",
       "supervisedSubjects carries an inventory of processes observed on the local machine. The section describes what KIND "
       "of automation is supervised, never what has been seen.",
       base(supervisedSubjects=[{
           "kind": "coding-agent", "identifier": "example-agent", "bindingMethod": "process-ancestry",
           "observedProcesses": [{"pid": 4812, "image": "C:/Users/jdoe/agent.exe"}],
       }]))

vector("invalid-semantic-request-field", "5.3", "INVALID",
       "The field name is not on the prohibited list, but its semantics express a request about consumer behaviour, which the "
       "section 5.3 catch-all forbids. Detecting this requires human review, so this vector is marked reviewOnly.",
       base(preferredHandling={"buildOutput": "deprioritise-scanning"}),
       notes="reviewOnly: a name-based validator cannot catch this. Implementers must apply the catch-all by judgement.")

# ------------------------------------------------------------ vocabulary (4.4)
vector("invalid-unknown-behaviour-token", "4.4 rule 1", "INVALID",
       "Behaviour token outside the version 1.0 vocabulary. The WHOLE declaration is invalid; the unknown entry is not skipped.",
       base(declaredBehaviours=[{
           "token": "process.inject", "scope": "system-wide",
           "components": ["ExampleSupervisor.exe"], "purpose": "Undefined token.",
       }]))

vector("invalid-unknown-scope", "4.4", "INVALID",
       "scope outside the closed enumeration.",
       base(declaredBehaviours=[{
           "token": "process.enumerate", "scope": "everything",
           "components": ["ExampleSupervisor.exe"], "purpose": "Bad scope value.",
       }]))

vector("invalid-purpose-too-long", "4.4 rule 3, 5.4", "INVALID",
       "purpose exceeds 200 characters.",
       base(declaredBehaviours=[{
           "token": "process.enumerate", "scope": "system-wide",
           "components": ["ExampleSupervisor.exe"], "purpose": "y" * 201,
       }]))

vector("invalid-purpose-operational-detail", "4.4 rule 3", "INVALID",
       "purpose names a port and an authentication scheme. Operational detail assists an attacker more than a consumer. "
       "Marked reviewOnly because catching every form of this needs judgement.",
       base(declaredBehaviours=[{
           "token": "network.listen-loopback", "scope": "self-only",
           "components": ["ExampleSupervisor.exe"],
           "purpose": "Listens on 127.0.0.1:54321 using a bearer token read from settings.json.",
       }]),
       notes="reviewOnly: the bundled validator flags an obvious port pattern only. Full enforcement is a review activity.")

vector("invalid-behaviour-component-not-declared", "4.4", "INVALID",
       "A declaredBehaviours entry references a component absent from the components list, so the behaviour cannot be bound "
       "to a hashed file.",
       base(declaredBehaviours=[{
           "token": "process.enumerate", "scope": "system-wide",
           "components": ["NotListed.exe"], "purpose": "References an undeclared component.",
       }]))

# ---------------------------------------------------------- working set (4.6)
vector("invalid-working-set-too-many", "5.4", "INVALID",
       "33 workingSet roots, one over the bound of 32.",
       base(workingSet=[
           {"root": "%%USERPROFILE%%/w{}".format(i), "reason": "build-output",
            "churn": "low", "source": "derived"} for i in range(33)
       ]))

vector("invalid-working-set-verb", "4.6", "INVALID",
       "A workingSet entry carries an action. The section is descriptive and has no verbs; a declarant must not be able to "
       "express a request even if it wants to.",
       base(workingSet=[{
           "root": "%USERPROFILE%/src", "reason": "build-output", "churn": "high",
           "source": "user-configured", "action": "exclude",
       }]))

vector("invalid-working-set-unknown-reason", "4.6", "INVALID",
       "reason outside the closed enumeration.",
       base(workingSet=[{
           "root": "%USERPROFILE%/src", "reason": "because-i-said-so", "churn": "high", "source": "install",
       }]))

vector("invalid-document-too-large", "5.4", "INVALID",
       "Every field is individually legal, but the document exceeds 64 KiB. The components array has no count bound of its "
       "own, so the document size limit is the backstop for every unbounded array in the schema.",
       base(components=[
           {"path": "component-{:04d}-with-a-deliberately-long-relative-path/binary.exe".format(i), "sha256": VALID_SHA}
           for i in range(700)
       ]))

# ------------------------------------------------------------- lifetime (5.4)
vector("invalid-expired", "5.4", "INVALID",
       "expiresUtc is in the past relative to the fixed evaluation time.",
       base(issuedUtc="2024-01-01T00:00:00Z", expiresUtc="2025-01-01T00:00:00Z"))

vector("invalid-issued-in-future", "5.4", "INVALID",
       "issuedUtc is in the future relative to the fixed evaluation time. A clock-skewed or backdated declarant.",
       base(issuedUtc="2030-01-01T00:00:00Z", expiresUtc="2031-01-01T00:00:00Z"))

vector("invalid-unknown-spec-version", "5.4", "INVALID",
       "Unrecognised specVersion. A consumer must not guess at a vocabulary it does not have.",
       base(specVersion="9.9"))

# ------------------------------------------------------------------ PII (5.1.8)
vector("invalid-pii-username", "5.1.8", "INVALID",
       "An absolute path disclosing a user name. Declarants must use environment-variable forms.",
       base(workingSet=[{
           "root": "C:/Users/jdoe/source/acme-secret-project", "reason": "build-output",
           "churn": "high", "source": "user-configured",
       }]))

vector("invalid-pii-sid", "5.1.8", "INVALID",
       "A security identifier in the document.",
       base(supervisedSubjects=[{
           "kind": "coding-agent", "identifier": "S-1-5-21-1004336348-1177238915-682003330-512",
           "bindingMethod": "process-ancestry",
       }]))

# ------------------------------------------------- runtime, not document (4.4 r2)
vector("invalid-under-declaration", "4.4 rule 2", "INVALID",
       "The document is well formed, but the declarant was observed terminating processes without declaring "
       "process.terminate. Under-declaration invalidates, so minimising is strictly worse than over-declaring.",
       base(),
       env={"signatureValid": True, "hashesMatch": True, "scope": "machine",
            "observedBehaviours": ["process.enumerate", "process.terminate"]},
       notes="Runtime case. Requires a consumer that observes behaviour, not only document validation.")

# ----------------------------------------------------- consumer conformance (5.2)
vector("consumer-per-user-scope", "5.2.5", "VALID_BUT_UNCREDITED",
       "A structurally valid declaration published in per-user scope. It is an assertion by whatever code runs as that "
       "user, including malware. A conforming consumer parses it and grants it nothing.",
       base(),
       env={"signatureValid": True, "hashesMatch": True, "scope": "user", "observedBehaviours": []},
       notes="Consumer test. Assert the per-user result is not treated as more credible than no declaration at all.")

vector("consumer-absence-is-not-negative", "5.2.3", "ABSENT",
       "No declaration exists. A conforming consumer must behave identically to the case where the format was never "
       "invented. Penalising absence would make the format coercive.",
       None,
       env={"signatureValid": False, "hashesMatch": False, "scope": "none", "observedBehaviours": []},
       notes="Consumer test. Assert byte-identical behaviour to a run with no declaration support compiled in.")

vector("invalid-bidi-override", "4.7, 5.4", "INVALID",
       "purpose contains a right-to-left override. Bidirectional control characters let a string render differently from "
       "the bytes a reviewer approved, so they are rejected at parse rather than left to consumer sanitisation.",
       base(declaredBehaviours=[{
           "token": "process.enumerate", "scope": "system-wide",
           "components": ["ExampleSupervisor.exe"],
           "purpose": "Reads the process list " + chr(0x202E) + "gnp.exe harmless",
       }]))

vector("invalid-control-character", "4.7, 5.4", "INVALID",
       "product.name contains an embedded NUL. Control characters truncate or corrupt in downstream consumers, so they are "
       "rejected at parse.",
       base(product={"name": "Example" + chr(0) + "Supervisor", "version": "1.0.0", "vendor": "Example Software"}))

vector("consumer-untrusted-strings", "5.2.6", "VALID",
       "Structurally valid, with hostile but legally encoded content in every free-text field. A conforming consumer "
       "sanitises before rendering and never interpolates these into a path, command, query or rule.",
       base(
           product={"name": "<script>alert(1)</script>", "version": "1.0.0", "vendor": "'; DROP TABLE t; --"},
           declaredBehaviours=[{
               "token": "process.enumerate", "scope": "system-wide",
               "components": ["ExampleSupervisor.exe"],
               "purpose": "../../../etc/passwd and $(rm -rf /) and {{7*7}} and %n%n",
           }],
       ),
       notes="Consumer test. Structural validity is expected; the assertion is about safe handling, not rejection.")

vector("consumer-duplicate-declarant-id", "4.1", "VALID",
       "Same declarantId as valid-minimal but a newer issuedUtc. A consumer resolves in favour of the newest, treats the "
       "older as stale, and reports the collision.",
       base(issuedUtc="2026-09-03T00:00:00Z"),
       notes="Consumer test. Pair with valid-minimal; assert this one wins and the collision is reported.")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    index = {
        "specVersion": SPEC_VERSION,
        "spec": "../automation-declaration-v1.md",
        "licence": "CC0-1.0",
        "evaluationTimeUtc": EVALUATION_TIME,
        "note": (
            "Environment facts live in each vector's 'env' object, never inside the declaration document, because spec "
            "section 4.3 forbids a document asserting its own validity. Vectors whose expect value is not VALID or "
            "INVALID exercise consumer behaviour rather than document validity."
        ),
        "expectValues": {
            "VALID": "The document is valid. A consumer may use it for explanation only (5.2.8).",
            "INVALID": "The consumer must treat the declaration as ABSENT (5.4).",
            "VALID_BUT_UNCREDITED": "Structurally valid; must be given no more weight than absence (5.2.5).",
            "ABSENT": "No declaration. Consumer behaviour must be identical to the no-format case (5.2.3).",
        },
        "vectors": [],
    }

    written = 0
    for v in VECTORS:
        doc = v.pop("_doc")
        entry = {k: val for k, val in v.items() if val is not None}
        if doc is None:
            entry.pop("file", None)
        else:
            with io.open(os.path.join(here, v["file"]), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
            written += 1
        index["vectors"].append(entry)

    with io.open(os.path.join(here, "index.json"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(index, indent=2, ensure_ascii=False) + "\n")

    print("wrote {} vector documents and index.json ({} entries)".format(written, len(index["vectors"])))


if __name__ == "__main__":
    main()
