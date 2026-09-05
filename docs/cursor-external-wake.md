# Cursor external wake (inbox + Foreman mailbox)

How to notify the Cursor agent when you are not in chat — with minimal token burn on idle polls.

## What we found about "cronjob" / plan tokens

- **No separate "cronjob token" line item** shows up in Cursor billing docs. [Automations](https://cursor.com/docs/cloud-agent/automations) run as **Cloud Agents** (Max Mode) and draw from your plan's **included API usage** first, then on-demand spend.
- That still matches the intent: **scheduled automations** are the right place for background "is there mail?" checks so you do not burn interactive Composer/Agent turns on empty polls.
- **Foreman MCP is localhost-only** (`http://localhost:54321/mcp`). Cloud automations **cannot** call it. Use the **file inbox** (`.cursor-inbox/`) for cloud/cron paths; use **Foreman mailbox** when Foreman is running and a **local** agent or probe can reach it.
- Foreman already implements the mailbox pattern ([June 9 Kosheen note](https://github.com)): `request_harness_review` → `list_ask_harness_requests` poll. `Foreman.TestHarness` is the reference client.

## Architecture (two lanes)

```
External party
  ├─ drop .cursor-inbox/*.md     ──► file lane (cloud + local)
  └─ Foreman request_harness_review(target: cursor) ──► mailbox lane (local MCP)
           │
           ▼
  Poll-CursorInbox.ps1  (cheap, no LLM)
           │  only if work
           ▼
  Cursor agent session OR Cursor Automation (cron/webhook)
```

## Lane 1 — File inbox (works everywhere)

**Trigger:** create `T:\TOOLS\.cursor-inbox\<name>.md` (or `.txt` / `.msg`).

**Process:** agent reads → acts → moves to `.cursor-inbox/processed/`.

Works with:

- Open Cursor agent (rule: `.cursor/rules/foreman-inbox-poll.mdc`)
- Local `/loop` watcher (below)
- Cursor Automation on a schedule or webhook (repo = `T:\TOOLS`, prompt checks only `.cursor-inbox/`)

## Lane 2 — Foreman mailbox (local, richer)

**Trigger (operator token):**

```text
request_harness_review(
  targetHarnessId: "cursor",
  systemPrompt: "Handle operator handoff.",
  prompt: "<what you need Cursor to do>",
  reason: "external wake"
)
```

**Trigger (harness-to-harness):** another harness uses the same tool; Foreman wraps it as attributed mail.

**Delivery:** live MCP notification if Cursor has an active Foreman session; otherwise queued until `list_ask_harness_requests`.

**Cheap probe (no LLM):**

```powershell
dotnet run --project T:\TOOLS\Foreman\src\Foreman.TestHarness -- --harness cursor --probe
```

Exit codes: `0` idle, `1` pending mail, `2` Foreman down. One JSON line on stdout.

## Local session watcher (lowest disruption while Cursor is open)

Uses the [Loop skill](file:///C:/Users/AxelW/.cursor/skills-cursor/loop/SKILL.md) pattern — **no agent tokens** until work exists.

```powershell
# Example: check every 15 minutes (adjust IntervalMinutes)
$interval = 15
while ($true) {
  Start-Sleep -Seconds ($interval * 60)
  & T:\TOOLS\Foreman\scripts\Poll-CursorInbox.ps1 -IntervalHint "${interval}m"
}
```

Arm with `notify_on_output` regex `^AGENT_LOOP_WAKE_CURSOR_INBOX` in an agent session. Increase `$interval` (30–60m) if you want fewer process wakes.

## Cursor Automation (cron — uses Cloud Agent budget)

Use when Cursor is closed but you still want periodic checks. **Guard prompt** (idle ≈ one short reply):

```text
Inbox poll only. Do not explore the repo.
1. List .cursor-inbox/ for *.md, *.txt, *.msg (ignore README and processed/). If none: reply exactly IDLE and stop.
2. Otherwise read each file, execute the request, move to .cursor-inbox/processed/.
```

Suggested schedule: **every 30–60 minutes** (not hourly on the nose if you have many automations). Tune down if noisy; tune up if you need faster file pickup.

**Webhook variant:** same prompt, trigger on HTTP POST from your own script when you drop a file (faster than cron, same token profile).

Draft prefill for the Automations editor: `Foreman/docs/cursor-inbox-automation-prefill.json` (import via Automations UI / `open_automation`).

> Foreman `mcp` action is **not** prefilled — localhost Foreman is not available to cloud agents. File inbox only for automations.

## Tuning disruption vs latency

| Knob | Effect |
|------|--------|
| Loop interval (`Poll-CursorInbox.ps1` / shell sleep) | Local wake latency while a session is open |
| Automation cron (`0 */1 * * *` vs `0 */2 * * *`) | Pickup when Cursor is closed |
| Webhook instead of cron | Event-driven; best token/latency tradeoff for file drops |
| Prompt "reply IDLE and stop" | Keeps empty cron runs cheap |
| Foreman `--probe` only in script | Avoids full agent MCP round-trips in the scheduler |

## Install templates

Canonical copies of the workspace-only inbox files live in `Foreman/docs/templates/`. `T:\TOOLS` is not a single git repo, so install (or refresh) them manually after clone or template updates: copy `Foreman/docs/templates/cursor-inbox-README.md` to `T:\TOOLS\.cursor-inbox\README.md`, and copy `Foreman/docs/templates/foreman-inbox-poll.mdc` to `T:\TOOLS\.cursor\rules\foreman-inbox-poll.mdc`. The live workspace paths are left untouched by Foreman commits.

## Files

| Path | Role |
|------|------|
| `.cursor-inbox/` | External file drop |
| `.cursor/rules/foreman-inbox-poll.mdc` | In-session poll rule |
| `Foreman/docs/templates/cursor-inbox-README.md` | Tracked template for `.cursor-inbox/README.md` |
| `Foreman/docs/templates/foreman-inbox-poll.mdc` | Tracked template for inbox poll rule |
| `Foreman/scripts/Poll-CursorInbox.ps1` | Cheap combined probe + loop sentinel |
| `Foreman/src/Foreman.TestHarness` `--probe` | Foreman-only exit-code probe |
| `Foreman/docs/cursor-inbox-automation-prefill.json` | Automation editor draft |

## Prerequisites

- Foreman tray running for mailbox lane (`localhost:54321`)
- Cursor `~/.cursor/mcp.json` foreman entry (Connect Agent in Foreman UI)
- For automations: on-demand billing / spend headroom per [Cloud Agents docs](https://cursor.com/docs/cloud-agent/automations)
