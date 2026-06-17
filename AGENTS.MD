# AI Agent Reference for ShieldDNS

---

## Token Efficiency Rules (CRITICAL — Read First)

These rules apply to **every response** without exception:

1. **Output minimal prose.** Bullet points only. No introductory sentences, no filler, no "Great question!", no "As requested".
2. **No walkthrough unless explicitly asked.** Never create or update `walkthrough.md` unless the user writes "walkthrough" or "summary" in their request.
3. **No implementation plan unless complex.** Skip planning artifacts for simple tweaks, single-file edits, bug fixes, or minor features. Plan only for major architectural changes.
4. **Short change summaries only.** After making changes, output ≤5 bullet points describing *what* changed and *why* — never a line-by-line description.
5. **No repeating file content.** Never echo back code you just wrote or edited. Reference filenames with links instead.
6. **No tool-call narration.** Do not describe what tool you are about to call. Just call it.
7. **Targeted file reads only.** Use `grep_search` or `view_file` with `StartLine`/`EndLine` to read only the relevant section. Never view an entire large file unless strictly necessary.
8. **Use the manifest first.** Before exploring the codebase, read `project_manifest.json` and `project_connections.json`. Do not walk directories recursively.
9. **Parallel tool calls.** Fire all independent tool calls in a single block. Never sequence calls that can run simultaneously.
10. **No re-summarizing artifacts.** After creating or updating an artifact, do NOT restate its contents — just link to it and note any open questions.
11. **Skip trivial confirmations.** Do not ask "Would you like me to proceed?" for obvious next steps. Just do them.
12. **No closing pleasantries.** End your response after the change summary. No "Let me know if you have questions!" etc.
13. **Omit unchanged layers.** If a change only affects the backend service, do not mention frontend or DB layers unless they are also modified.
14. **Reuse subagents.** Send follow-up tasks to an existing idle subagent instead of spawning a new one.
15. **Suppress test output noise.** When running tests, only report failures. Do not paste successful test output unless the user asks.
16. **Delegate with subagents.** For any research-heavy, multi-file, or parallelizable task, spin up a subagent instead of doing it inline. This keeps your own context lean and reduces token usage for the main conversation.
17. **Reuse idle subagents.** Send follow-up instructions to an already-running subagent via `send_message` — never spawn a new one for the same task thread.
18. **Don't poll subagents.** After launching a subagent, stop calling tools. The system wakes you automatically when the subagent replies.
19. **Subagent scope = minimal.** Give each subagent one focused goal. Never dump the entire task into a single subagent prompt.
20. **Prefer `research` subagent for read-only work.** Codebase exploration, grep searches, file reads, and web lookups should go to the `research` subagent so the main agent stays focused on writing code.
21. **Prefer `self` subagent for isolated execution.** Use the `self` subagent for tasks that need write access in a separate context (e.g. branch workspace edits, test runs, parallel fixes on different modules).

---

## Subagent Strategy

Use subagents proactively whenever a task has independent subtasks, requires heavy research, or would bloat the main context:

| Scenario | Action |
|---|---|
| Reading/searching codebase before coding | Delegate to `research` subagent |
| Parallel bug fixes across multiple modules | Spawn one `self` subagent per module with `branch` workspace |
| Exploring docs / web while coding continues | Delegate to `research` subagent, continue main task |
| Running tests after a fix | Delegate to `self` subagent, await result |
| Long GitHub API analysis + code fix | Research subagent reads issues; main agent applies fix |

**Workspace modes:**

- `inherit` — shares parent workspace (default, for read or simple edits)
- `branch` — isolated copy (for concurrent writes to same files)
- `share` — shared repo, independent branch (for parallel feature work)

**Never** do sequential research → code → test all inline in the main agent when any step can be offloaded.

---

## Project Manifest & Connection Map (Single Source of Truth)

Read these before exploring the codebase — they cover the entire file tree, endpoints, models, and feature flows:

- **Manifest**: `project_manifest.json` — Go backend endpoints, frontend views, API mappings, file tree.
- **Connections**: `project_connections.json` — file-level mapping for specific full-stack feature flows (DNS core, MFA, Geo-block, system diagnostics, rules/presets).

---

## Codebase Architecture

### Backend (`/admin`)

| Area | Path |
|---|---|
| App entry & routing | `admin/main.go` |
| Endpoints / controllers | `admin/api_*.go` |
| Core logics (DNS / DB) | `admin/dns.go`, `admin/db.go` |
| Threat intel & Geo-block | `admin/geo.go`, `admin/malicious.go` |
| Multi-factor Auth (MFA) | `admin/auth.go`, `admin/api_mfa.go` |
| Backup & Restore | `admin/crypto_backup.go` |

### Frontend (`/admin/www/admin`)

| Area | Path |
|---|---|
| Index template | `admin/www/admin/index.html` |
| App module logic | `admin/www/admin/js/app.js` |
| Navigation controller | `admin/www/admin/js/core/navigation.js` |
| Render helpers | `admin/www/admin/js/ui/renderers.js` |
| Service API routes | `admin/www/admin/js/services/api.js` |

---

## CLI Commands

| Task | Command | Dir |
|---|---|---|
| Backend compile | `go build -o shielddns-admin ./admin` | Root |
| Run Go backend locally | `go run admin/main.go` | Root |
| Run backend tests | `go test ./admin/...` | Root |
