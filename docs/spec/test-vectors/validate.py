#!/usr/bin/env python3
"""Reference validator and conformance runner for the Automation Declaration format v1.0.

CC0 1.0. Run from this directory: python validate.py

This implements the mechanically checkable subset of spec sections 4 and 5.4. It is a
reference for implementers, not a normative artifact: where this code and the
specification disagree, the specification wins.

Two requirements are deliberately NOT implemented here, because they are structural
properties of a consumer rather than properties of a document:

  5.2.1  A declaration, or its absence, must never be an input to a detection,
         scoring or blocking decision. Test this by asserting that no code path
         exists from declaration parsing to a verdict. It is checkable by inspection.
  5.2.3  Absence must not be treated as a negative signal. Test this by asserting
         byte-identical behaviour to a build with no declaration support at all.

The vectors marked with those sections carry notes saying the same thing.
"""

import json
import io
import os
import re
import sys

SPEC_VERSIONS = {"1.0"}
MAX_DOC_BYTES = 64 * 1024
MAX_PURPOSE = 200
MAX_WORKING_SET = 32

BEHAVIOUR_TOKENS = {
    "process.enumerate", "process.inspect-command-line", "process.subscribe-creation",
    "process.terminate", "process.suspend", "process.read-memory",
    "filesystem.watch", "filesystem.write-outside-install", "filesystem.read-user-documents",
    "filesystem.plant-canary",
    "registry.write-run-key", "registry.write-outside-own-hive", "registry.read-security-state",
    "network.listen-loopback", "network.listen-external", "network.connect-outbound",
    "privilege.request-elevation", "privilege.run-elevated-helper", "privilege.install-service",
    "script.observe-content",
    "telemetry.consume-os-event-log", "telemetry.consume-etw", "telemetry.read-security-product-state",
}
SCOPES = {"self-only", "supervised-subjects-only", "working-set-only", "system-wide"}
WS_REASONS = {"build-output", "package-cache", "intermediate-artifacts", "snapshot-store"}
WS_CHURN = {"low", "medium", "high"}
WS_SOURCES = {"install", "user-configured", "derived"}

# Section 5.3. Permanently prohibited, in any version, at any nesting depth.
PROHIBITED = {
    "action", "allow", "allowlist", "exclude", "exclusion", "exempt", "exemption",
    "trust", "trusted", "suppress", "suppression", "whitelist", "bypass", "skip",
    "ignore", "priority", "severity", "confidence", "verdict", "signed", "verified",
    "approved",
}

# Section 4. The schema is closed: these are the only permitted keys at each level.
TOP = {"specVersion", "declarantId", "issuedUtc", "expiresUtc", "product", "components",
       "declaredBehaviours", "supervisedSubjects", "workingSet", "contactUri"}
REQUIRED = {"specVersion", "declarantId", "issuedUtc", "expiresUtc", "product", "components",
            "declaredBehaviours"}
SHAPES = {
    "product": {"name", "version", "vendor"},
    "components": {"path", "sha256"},
    "declaredBehaviours": {"token", "scope", "components", "purpose"},
    "supervisedSubjects": {"kind", "identifier", "bindingMethod"},
    "workingSet": {"root", "reason", "churn", "source"},
}

SID = re.compile(r"S-1-5-21-[\d-]{6,}")
USERPATH = re.compile(r"[A-Za-z]:[\\/]Users[\\/](?!Public\b)[A-Za-z0-9._-]+", re.I)
PORTISH = re.compile(r":\d{2,5}\b")
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def walk_strings(node, path="$"):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from walk_strings(v, path + "." + k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_strings(v, path + "[%d]" % i)
    elif isinstance(node, str):
        yield path, node


def walk_keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from walk_keys(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk_keys(v)


def validate(doc, env, now, raw_bytes):
    """Return a list of failure reasons. Empty list means the document is valid."""
    bad = []

    # 4.3 / 5.2.4. Environment facts first: nothing else matters if identity fails.
    if not env.get("signatureValid"):
        bad.append("4.3: signature did not verify")
    if not env.get("hashesMatch"):
        bad.append("4.3: a component hash does not match the file on disk")

    if len(raw_bytes) > MAX_DOC_BYTES:
        bad.append("5.4: document exceeds %d bytes" % MAX_DOC_BYTES)

    if not isinstance(doc, dict):
        return bad + ["4: document root is not an object"]

    # 5.3. Prohibited names, at any depth, before anything else is considered.
    for k in walk_keys(doc):
        if k.lower() in PROHIBITED:
            bad.append("5.3: prohibited field '%s'" % k)

    # 5.3 / 5.5. Closed schema at every level.
    for k in doc:
        if k not in TOP:
            bad.append("5.3: unknown top-level field '%s'" % k)
    for k in REQUIRED - set(doc):
        bad.append("4: missing required field '%s'" % k)
    for section, allowed in SHAPES.items():
        val = doc.get(section)
        entries = val if isinstance(val, list) else ([val] if isinstance(val, dict) else [])
        for e in entries:
            if not isinstance(e, dict):
                continue
            for k in e:
                if k not in allowed:
                    bad.append("5.3: unknown field '%s' in %s" % (k, section))

    # 4.7. No control or bidirectional override characters in any string.
    for path, s in walk_strings(doc):
        for ch in s:
            o = ord(ch)
            if o in BIDI:
                bad.append("4.7: bidirectional override U+%04X in %s" % (o, path))
                break
            if o < 0x20 or o == 0x7F:
                bad.append("4.7: control character U+%04X in %s" % (o, path))
                break

    # 5.4. Version and lifetime.
    if doc.get("specVersion") not in SPEC_VERSIONS:
        bad.append("5.4: unrecognised specVersion %r" % doc.get("specVersion"))
    issued, expires = doc.get("issuedUtc", ""), doc.get("expiresUtc", "")
    if issued and issued > now:
        bad.append("5.4: issuedUtc is in the future")
    if expires and expires < now:
        bad.append("5.4: expiresUtc has passed")

    # 4.4. Behaviour vocabulary, scope, purpose bounds, component binding.
    declared = set()
    known_components = {c.get("path") for c in doc.get("components", []) if isinstance(c, dict)}
    for b in doc.get("declaredBehaviours", []):
        if not isinstance(b, dict):
            bad.append("4.4: declaredBehaviours entry is not an object")
            continue
        tok = b.get("token")
        declared.add(tok)
        if tok not in BEHAVIOUR_TOKENS:
            bad.append("4.4 rule 1: unknown behaviour token %r" % tok)
        if b.get("scope") not in SCOPES:
            bad.append("4.4: unknown scope %r" % b.get("scope"))
        purpose = b.get("purpose", "")
        if len(purpose) > MAX_PURPOSE:
            bad.append("5.4: purpose exceeds %d characters" % MAX_PURPOSE)
        if PORTISH.search(purpose):
            bad.append("4.4 rule 3: purpose appears to name a port, which is operational detail")
        for c in b.get("components", []):
            if c not in known_components:
                bad.append("4.4: behaviour references undeclared component %r" % c)

    # 4.4 rule 2. Under-declaration, observed at runtime rather than in the document.
    for obs in env.get("observedBehaviours", []):
        if obs not in declared:
            bad.append("4.4 rule 2: observed undeclared behaviour %r" % obs)

    # 4.6. Working set bounds and closed enumerations.
    ws = doc.get("workingSet", [])
    if len(ws) > MAX_WORKING_SET:
        bad.append("5.4: %d workingSet roots exceeds the bound of %d" % (len(ws), MAX_WORKING_SET))
    for e in ws:
        if not isinstance(e, dict):
            continue
        if e.get("reason") not in WS_REASONS:
            bad.append("4.6: unknown workingSet reason %r" % e.get("reason"))
        if e.get("churn") not in WS_CHURN:
            bad.append("4.6: unknown workingSet churn %r" % e.get("churn"))
        if e.get("source") not in WS_SOURCES:
            bad.append("4.6: unknown workingSet source %r" % e.get("source"))

    # 5.1.8. No personally identifying information.
    for path, s in walk_strings(doc):
        if SID.search(s):
            bad.append("5.1.8: security identifier in %s" % path)
        if USERPATH.search(s):
            bad.append("5.1.8: user-name-bearing path in %s" % path)

    return bad


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    index = json.load(io.open(os.path.join(here, "index.json"), encoding="utf-8"))
    now = index["evaluationTimeUtc"]

    passed = failed = 0
    for v in index["vectors"]:
        expect = v["expect"]
        if "file" not in v:
            actual = "ABSENT"
            reasons = []
        else:
            raw = io.open(os.path.join(here, v["file"]), "rb").read()
            doc = json.loads(raw.decode("utf-8"))
            reasons = validate(doc, v["env"], now, raw)
            if reasons:
                actual = "INVALID"
            elif v["env"].get("scope") == "user":
                actual = "VALID_BUT_UNCREDITED"
            else:
                actual = "VALID"

        ok = actual == expect
        passed += ok
        failed += not ok
        mark = "pass" if ok else "FAIL"
        print("%-4s %-42s expect=%-22s actual=%s" % (mark, v["id"], expect, actual))
        if not ok:
            print("       reasons: %s" % (reasons or "none"))

    print("\n%d passed, %d failed, %d total" % (passed, failed, passed + failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
