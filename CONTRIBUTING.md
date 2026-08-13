# Contributing to TraceBrake

TraceBrake is alpha software for local AI-agent safety oversight. Bug reports, false-positive tuning, docs polish, and small focused pull requests are welcome.

## Prerequisites

- .NET 10 SDK preview. CI uses the preview channel.
- Windows 10/11 x64 for the full tray app and monitor.
- A working `dotnet` on `PATH`.

TraceBrake runs at normal user integrity by default. No admin/UAC prompt is required except for the optional elevated network sidecar.

## Build And Test

The solution file is `Foreman.slnx`.

```powershell
dotnet build .\Foreman.slnx -c Release
dotnet test .\Foreman.slnx -c Release
```

CI runs restore, build, and tests on `windows-latest`.

## Project Layout

| Project | Responsibility |
| --- | --- |
| `Foreman.Core` | Platform-agnostic events, models, heuristics, behavior tracking, settings, profiles, and escalation logic. |
| `Foreman.Monitor` | Windows process watching, tree attribution, harness classification, I/O polling, hang/orphan detection, and MCP inventory. |
| `Foreman.McpServer` | Local Kestrel/MCP host, bearer-token auth, tool registry, and connected-session tracking. |
| `Foreman.App` | WPF tray app, dashboard, settings, alert detail, and connection UI. |
| `Foreman.EtwSidecar` | Optional elevated ETW sidecar for per-process network attribution and decoy-credential read-auditing. |
| `Foreman.Guardian` | Optional LocalSystem guardian service: tamper-resistant signing of Foreman's own integrity seal (off by default). |

Tests live under `tests/`.

## Detection Rules

Detection rules are JSON files grouped by category.

- Source copies live in `data/patterns/*.json`.
- Embedded shipping copies live in `src/Foreman.Core/patterns/*.json`.
- Keep both locations in sync when adding or changing a rule.

Each rule should have:

- a stable `id`, prefixed by category, such as `cred-013`;
- a short `name`;
- a `severity` of `info`, `low`, `medium`, `high`, or `critical`;
- a safe, category-level `description`;
- a .NET regex `pattern`;
- matching tests.

Avoid putting working offensive one-liners in issue prose, PR titles, or docs. The rule pattern and a safe behavior-level explanation are enough.

## Product And Design Standards

TraceBrake is a safety tool, not a novelty tray utility. Public-facing changes should keep that tone:

- Prefer "safety monitor", "oversight", "audit", "review", and "accountability" over vague cleanup language.
- Be precise about trust boundaries. TraceBrake is not a sandbox and should not be described as one.
- Treat false positives as product bugs worth tuning.
- Keep UI copy calm and direct. Avoid theatrical destructive labels.
- Preserve privacy: do not include tokens, private paths, project names, or command output in screenshots or examples.
- New artwork must be original, generated specifically for TraceBrake, or otherwise GPL-compatible.

## Pull Requests

- Branch from `main`.
- Keep PRs focused.
- Run build and tests before pushing.
- Add tests for new behavior, especially detection rules, MCP tools, process attribution, or escalation logic.
- Mention changes to the MCP surface, token handling, installer behavior, or detection categories in the PR description.

The PR template includes a short safety/privacy checklist. Please fill it in instead of deleting it.

## Security

Report vulnerabilities privately through GitHub Security Advisories or by email as described in `SECURITY.md`. Do not open public issues for suspected vulnerabilities.

## Release Checklist

Before publishing binaries, use `docs/release-checklist.md`.

## License

TraceBrake is licensed under GPL-3.0-or-later. By contributing, you agree that your contributions are licensed under the same terms.
