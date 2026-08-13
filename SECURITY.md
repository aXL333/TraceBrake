# Security Policy

TraceBrake is a local Windows safety monitor for AI coding agents. It watches process trees, applies heuristic command analysis, reads selected local harness configuration files, and exposes a local MCP server at `http://localhost:54321/mcp` by default.

TraceBrake is alpha software. It improves visibility and reviewability, but it is not a sandbox and does not claim to stop a determined same-user attacker.

## Supported Versions

Only current code receives security fixes.

| Version | Supported |
| --- | --- |
| Latest GitHub pre-release/release, once published | Yes |
| `main` | Yes |
| Older builds | No |

If you are running an older local build, update to the latest release or `main` before reporting unless the vulnerability specifically concerns the update path.

## Reporting A Vulnerability

Please report privately. Do not open a public issue, discussion, pull request, or social post for a suspected vulnerability until a fix is available and disclosure has been coordinated.

Preferred channels:

1. **GitHub Security Advisories** - use the repository Security tab and choose "Report a vulnerability".
2. **Email** - `xredux@protonmail.com`, subject line `TraceBrake security`.

A useful report includes:

- Affected commit, tag, or installer version.
- Windows version and whether TraceBrake was launched from source or an installer.
- Reproduction steps.
- Expected impact.
- Relevant TraceBrake settings, especially MCP port, run-at-login, `RunElevated`, `ScanMcpTools`, custom harnesses, and MCP client configuration.

## Response Window

This is currently a single-maintainer project, so timelines are best-effort rather than an SLA.

- Acknowledgement: typically within about a week.
- Initial assessment: typically within about two weeks of acknowledgement.
- Fix timeline: depends on impact and complexity, and will be discussed in the report thread.

If there is no response within two weeks, a polite follow-up on the same channel is welcome.

## Scope

TraceBrake is local desktop software. There is no hosted service, account system, cloud backend, or telemetry.

### In Scope

- MCP server and HTTP/SSE endpoint behavior, including authentication bypasses or unintended access beyond the documented tool set.
- The local HTTP listener binding beyond loopback.
- Token handling: generation, storage, ACL hardening, and bearer-token verification.
- Process and command-line parsing crashes, hangs, or resource exhaustion caused by hostile or malformed local process metadata.
- Pattern/profile/config file handling where a crafted file can crash TraceBrake or cause unsafe behavior.
- Installer behavior, per-user install paths, run-at-login registration, and release artifact tampering.
- Privilege/integrity boundary issues, especially anything that causes TraceBrake's main UI/MCP server to run elevated unintentionally or lets an untrusted process influence TraceBrake's own execution.
- Optional elevated ETW sidecar issues when `RunElevated` is enabled.
- Optional outbound MCP tool-description scan behavior when `ScanMcpTools` is enabled.

### Out Of Scope

- Missed detections or false positives in heuristic rules. Those are bugs/tuning requests, not security vulnerabilities.
- Vulnerabilities in Claude Code, Codex, OpenCode, T3 Code, or other monitored agents.
- A same-user local attacker reading process command lines or otherwise doing what the user's account can already do.
- Roadmap features that are not implemented.
- Issues requiring a compromised OS, physical access, or disabling Windows security features.
- Denial of service that requires the reporter to already control the machine and user account TraceBrake runs under.

If unsure, report privately and ask.

## MCP Bridge Threat Model

TraceBrake's MCP tools are served on localhost. The `/health` endpoint is intentionally open for liveness checks. The `/mcp` endpoint requires an `Authorization: Bearer <token>` header.

The token is generated on first run and stored at `%LocalAppData%\TraceBrake\mcp.token`. Upgraded Foreman installations migrate the complete data directory before security-sensitive subsystems start. TraceBrake attempts to restrict the token file to the current Windows user. This protects against other local users when filesystem ACLs are enforced, but it does **not** protect against another process already running as the same user.

Important boundaries:

- A same-user process that can read the token can call TraceBrake's MCP tools.
- TraceBrake MCP tools do not grant a harness direct kill authority.
- High and Critical alerts cannot be acknowledged through MCP; the operator must use the TraceBrake UI.
- Ask Harness delivery is advisory. It uses MCP client/session identity for routing prompts, not authorization.
- The server should bind only to loopback. Remote reachability is in scope for private reporting.

## Detection Content

TraceBrake ships detection patterns under `data/patterns/` and embedded copies under `src/Foreman.Core/patterns/`. They are descriptive signatures used to flag risky command shapes for review. They are not runnable exploit tooling and do not execute anything.

Detection improvements are welcome as normal pull requests. Avoid including working attack one-liners in issue titles, PR titles, or prose; the regex pattern and safe category-level explanation are enough.
