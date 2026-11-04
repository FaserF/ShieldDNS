# AI Agent Reference for ShieldDNS

---

## Core Operational & Token Efficiency Rules

- **Minimal Prose**: Bullet points only (≤5 items for change summaries). No filler, pleasantries, or tool-call narration.
- **No Unrequested Artifacts**: Never create implementation plans (unless complex architectural change) or walkthroughs (unless explicitly requested).
- **Targeted Reads & Links**: Use targeted line ranges (`StartLine`/`EndLine`). Never echo back code. Reference files with markdown links.
- **Proactive Subagents**: Delegate research/exploration to `research` subagents and test/module fixes to `self` subagents. Do not poll.
- **Manifest First**: Consult `project_manifest.json` and `project_connections.json` before codebase exploration.
- **Tests & Linters**: Report failures only. Verify before concluding tasks. Default to English (EN).

---

## Subagent Strategy

| Scenario | Subagent & Workspace Mode |
|---|---|
| Reading/searching codebase or docs | `research` (`inherit`) |
| Bug fixes across multiple modules / features | `self` (`branch` or `share`) |
| Running tests & linter verification | `self` (`inherit`) |

---

## Project Manifest & Connection Map (Single Source of Truth)

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
