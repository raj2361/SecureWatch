# SecureWatch — Multi-Agent SIEM & Endpoint Monitoring System

SecureWatch is a lightweight but genuinely layered **Security Information
and Event Management (SIEM)** platform, built as a college cybersecurity
project and upgraded incrementally into something closer to a small-scale
SOC platform: multi-agent support (Windows + Linux) with guided
provisioning, role-based access control, MITRE ATT&CK mapping with a
visual heatmap, risk scoring, a correlation engine that groups related
alerts into investigable cases, a full alert investigation workflow with
status escalation, and a glassmorphism SOC dashboard.

It collects real system, login, process, network, and security-log data
from monitored machines — Windows and Linux — stores it centrally in
SQLite, runs rule-based threat detection with automatic correlation, and
presents everything through a dark, cybersecurity-themed web console.

---

## ✨ Features

**Core SIEM**
- 🖥️ Cross-platform endpoint agent — **Windows** (event log login/security
  events via `pywin32`) and **Linux** (real `/var/log/auth.log` parsing
  for SSH login attempts and `sudo` usage) — plus OS-agnostic process,
  network, and heartbeat collection on both
- 🧭 **Agents provisioning page** (admin-only) — pick Windows or Linux, get
  a guaranteed-unique Agent ID and a ready-to-copy install command with
  the correct server URL auto-detected from the browser, live
  "waiting for agent…" → "connected!" status
- 🏷️ **Multi-agent identity**: every endpoint gets a stable, explicit
  `Agent ID` (e.g. `Agent-01`) independent of hostname, so cloned VMs,
  re-imaged machines, or two machines sharing a hostname never collide
- 🗄️ SQLite-backed event store with per-agent log/alert isolation
- 🔐 Session-based authentication with **RBAC** — `admin` / `analyst` /
  `viewer` roles, enforced on every mutating route
- 🛡️ CSRF protection (Flask-WTF) and rate limiting (Flask-Limiter) on the
  login form and session-authenticated API calls

**Detection & Threat Intelligence**
- 🚨 Rule-based detection engine (6 rules — see table below), with:
  - **Event normalization** — every log type mapped to a common
    field schema (`user`, `src_ip`, `dest_ip`, `process`, `file_hash`)
  - **MITRE ATT&CK mapping** on every alert, with real technique
    descriptions
  - **MITRE ATT&CK Heatmap page** — the full 14-tactic matrix, cells
    colored by real hit count and severity (never fabricated coverage —
    undetected techniques render as an honest gray)
  - **Risk scoring** (0–100) on both alerts and endpoints, boosted by
    alert frequency, rising and falling live as alerts open/escalate/close
  - **Correlation engine** — automatically groups related alerts on the
    same endpoint into investigable **Cases**
  - **Alert suppression** — admin-tunable, globally or per-endpoint, with
    optional expiry
  - Malware file detection via VirusTotal (optional API key)
- 🔎 **Threat Hunting page** — `field:value` ad-hoc search across every
  log's normalized fields (`user`, `src_ip`, `dest_ip`, `process`,
  `file_hash`, `event_id`), not just substring match; save frequent
  queries for the whole team to reuse

**Alert Investigation Workflow**
- 📄 Dedicated full-page investigation view at `/alerts/<id>` — alert
  details, MITRE panel with description, Incident Summary card
  (affected endpoint, its open-alert count, its risk score, a
  deterministic recommended-action hint), analyst action buttons, and an
  Evidence panel of real time-windowed logs from the same endpoint
- 🔄 Full status flow: **Open → Acknowledged → Escalate → In Progress →
  Close → Reopen** — escalating bumps severity and recomputes risk
  scores live; every transition (plus notes/evidence) feeds one
  computed, always-consistent investigation timeline
- 👤 Analyst assignment ("Assign To Me"), investigation notes, and
  evidence attachments — shared infrastructure between alerts and cases,
  not two parallel systems

**Dashboard & UI**
- 🎨 Dark glassmorphism SOC theme — persistent sidebar, translucent
  blurred cards, gradient buttons, animated stat cards
- 📊 Security Score gauge (transparent, explainable), Endpoint Health,
  System Status chips, per-endpoint Risk badges sorted highest-first
- 📈 Interactive Chart.js visualizations: log volume, logs-by-severity,
  alert-severity pie, stacked Attack Timeline (alerts/hour by severity)
- 📡 Live Activity Feed, Top Threats ranking (real alert-frequency data)
- 🔔 Toast notifications on every action
- ✅ Case status workflow (open → investigating → resolved)
- 🔍 Live log viewer + Alerts page, both filterable by **Agent**,
  severity, status, log type, with search and pagination

**Code quality**
- 🧱 Repository + Service layer pattern (for auth, incidents, suppression,
  investigation, agent reservations, saved searches, users) layered over
  the original model files — zero breakage, fully backward compatible
- 🧾 Input validation, structured error handling, rotating application
  logs, idempotent database migrations that never touch existing data

---

## 🗂️ Project Structure

```
securewatch/
├── app.py                        # Flask application factory / entry point
├── config.py                     # Environment-aware config (Dev/Prod/Test), RBAC roles
├── requirements.txt              # Server dependencies
├── database/
│   ├── schema.sql                 # Fresh-install SQLite schema
│   ├── init_db.py                 # DB init + admin seed script
│   ├── migrate.py                 # Idempotent migration runner for EXISTING databases
│   ├── manage_users.py            # CLI to create/list/update analyst & viewer accounts
│   └── blacklisted_ips.txt        # Seeded IP blacklist (auto-created)
├── models/                        # Original data-access layer (still used directly by
│   │                               # logs/endpoints/base alert CRUD, and the Hunt query engine)
│   ├── db.py / user_model.py / log_model.py / alert_model.py / endpoint_model.py
├── repositories/                  # Newer data-access layer (wraps models/*, used by
│   │                               # auth, cases, suppression, investigation, agent
│   │                               # reservations, saved searches, users)
│   ├── user_repository.py / incident_repository.py / suppression_repository.py
│   ├── investigation_repository.py / agent_reservation_repository.py
│   ├── saved_search_repository.py
├── services/                      # Business-logic layer (currently: auth)
│   └── auth_service.py
├── routes/                        # Flask blueprints
│   ├── auth_routes.py             # Login/logout
│   ├── dashboard_routes.py        # Dashboard/heatmap/endpoint/alert page routes + JSON APIs
│   ├── api_routes.py              # Agent-facing REST API (multi-agent aware)
│   ├── alert_routes.py            # Ack/close/escalate/reopen + investigation workflow
│   ├── incident_routes.py         # Cases: list/detail/status + investigation workflow
│   ├── detection_routes.py        # Admin-only suppression rule management
│   ├── agents_routes.py           # Agents provisioning page + Agent ID reservation
│   └── hunt_routes.py             # Threat Hunting page + saved searches
├── detection/                     # Detection engine
│   ├── engine.py                   # Orchestrates normalize -> rules -> correlate
│   ├── rules.py                    # The 6 detection rules
│   ├── mitre.py                    # Rule -> MITRE ATT&CK mapping + descriptions
│   ├── risk.py                     # 0-100 risk scoring (alert + endpoint)
│   ├── normalizer.py               # Common-field event normalization (now queried back by Hunt)
│   ├── suppression.py              # Suppression check before alert creation
│   ├── correlation.py              # Groups related alerts into Cases, refreshes endpoint risk
│   └── virustotal.py               # Optional malware file-hash lookup
├── utils/                         # Logging, validation, RBAC, CSRF/rate-limit extensions
│   ├── auth_utils.py / rbac.py / validators.py / logger.py / extensions.py
├── templates/                     # Jinja2 HTML templates (Bootstrap 5 + glassmorphism CSS)
│   ├── base.html                   # Sidebar + topbar shell
│   ├── login.html / dashboard.html / logs.html / alerts.html / alert_detail.html
│   ├── cases.html / endpoints.html / endpoint_detail.html
│   ├── heatmap.html / agents.html / hunt.html / errors.html
├── static/
│   ├── css/style.css               # Dark glassmorphism SOC theme (design tokens + components)
│   └── js/                         # dashboard.js, logs.js, alerts.js, alert_detail.js,
│                                    # cases.js, endpoints.js, endpoint_detail.js,
│                                    # heatmap.js, agents.js, hunt.js, badges.js, toast.js, ticker.js
├── agent/
│   ├── securewatch_agent.py       # Cross-platform agent (Windows + Linux)
│   └── requirements.txt           # Agent-side dependencies
├── logs/                          # Application runtime logs (auto-created)
├── screenshots/                   # Screenshot placeholders (see below)
└── README.md
```

---

## ⚙️ Requirements

- Python 3.10+
- pip
- (Windows agent only) `pywin32` for full event-log collection
- (Linux agent) read access to `/var/log/auth.log` or `/var/log/secure`
  — typically requires `sudo` or membership in the `adm` group

---

## 🚀 Installation & Setup

### 1. Enter the project folder
```bash
cd securewatch
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### 3. Install server dependencies
```bash
pip install -r requirements.txt --break-system-packages
```
(Omit `--break-system-packages` if you're inside a virtual environment.)

### 4. Configure environment variables (optional but recommended)
Create a `.env` file in the project root:
```env
SECRET_KEY=replace-this-with-a-long-random-string
ADMIN_USERNAME=admin
ADMIN_PASSWORD=ChangeMe123!
AGENT_API_KEY=shared-secret-between-server-and-agents
LOGIN_RATE_LIMIT=10 per minute
VT_API_KEY=your_virustotal_api_key_here   # optional - leave blank to skip malware checks
```
If you skip this step, sensible development defaults from `config.py` are used
— **but you must change them before any real deployment.**

### 5. Initialize (or upgrade) the database
**Fresh install:**
```bash
python database/init_db.py
```
**Already have a `securewatch.db` from an earlier version of this project?**
Don't wipe it — just run the migration, which adds every new table/column
(and safely rebuilds the endpoints table if it still has an old-style
hostname constraint) without touching your existing logs/alerts/cases:
```bash
python database/migrate.py
```

### 6. Run the server
```bash
python app.py
```
The console is now available at **http://localhost:5000**.
Log in with the admin username/password you configured (default:
`admin` / `Admin@123` — **change this immediately**).

### 7. Create analyst/viewer accounts (optional)
There's no public signup page by design — provision accounts via the CLI:
```bash
python database/manage_users.py create analyst1 --role analyst
python database/manage_users.py create viewer1 --role viewer
python database/manage_users.py list
```

### 8. Add an endpoint agent (recommended: use the Agents page)
Log in as admin, click **Agents** in the sidebar, pick Windows or Linux —
you'll get a guaranteed-unique Agent ID and the exact install command
(with your real server URL and API key already filled in) to copy onto
the target machine. Click **Copy Command**, run it there, and the page
shows "Connected!" the moment it checks in.

**Or configure it manually:**
```bash
cd agent
pip install -r requirements.txt --break-system-packages
```

**Windows:**
```powershell
pip install pywin32   # optional, enables real login/security event collection
python securewatch_agent.py --server http://<server-ip>:5000 --api-key securewatch-agent-key --agent-id Agent-01
```

**Linux / Kali:**
```bash
sudo python3 securewatch_agent.py --server http://<server-ip>:5000 --api-key securewatch-agent-key --agent-id Agent-02
```
`sudo` (or `adm` group membership) is required to read `/var/log/auth.log`.
Without it, the agent still runs and reports process/network/heartbeat
data — it just prints a `[WARN]` and skips login/security collection.

Run `--once` to send a single collection cycle instead of looping, useful for testing:
```bash
python securewatch_agent.py --server http://<server-ip>:5000 --api-key <key> --agent-id Agent-01 --once
```

**Adding Agent-03, Agent-04, Agent-05:** same process via the Agents page
(each visit generates a fresh, reserved, non-colliding ID) or the same
manual command with a different `--agent-id`. No server-side changes needed.

---

## 🔑 Default Credentials (change these!)

| Field    | Default Value |
|----------|----------------|
| Username | `admin`        |
| Password | `Admin@123`    |
| Role     | `admin`        |

Change `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env` **before** running
`init_db.py` for the first time, or update the password directly afterwards.

### Roles

| Role | Can do |
|------|--------|
| `viewer` | Read everything (dashboard, logs, alerts, cases, endpoints, heatmap, hunt) — no write actions |
| `analyst` | Everything a viewer can, plus: acknowledge/escalate/close/reopen alerts, add notes/evidence, assign alerts/cases, transition case status, save hunt queries |
| `admin` | Everything an analyst can, plus: manage users, tune detection rules (create/remove suppressions), access the Agents provisioning page |

---

## 📡 REST API Documentation

### Agent-facing endpoints (machine auth via `X-API-KEY`)

All require the header:
```
X-API-KEY: <your AGENT_API_KEY>
```

#### `GET /api/agent/ping`
Health check. Returns `{"status": "ok"}`.

#### `POST /api/agent/checkin`
Registers or refreshes an endpoint. `agent_id` and `os_type` are optional
but recommended for multi-agent setups.
```json
{
  "hostname": "DESKTOP-ABC123",
  "agent_id": "Agent-01",
  "os_type": "windows",
  "os_version": "Windows 11 Pro 23H2",
  "ip_address": "192.168.1.42",
  "agent_version": "2.0.0"
}
```

#### `POST /api/agent/logs`
Submits a batch of collected events (max 500 per request).
```json
{
  "hostname": "DESKTOP-ABC123",
  "agent_id": "Agent-01",
  "logs": [
    {
      "log_type": "login",
      "source": "Windows Security Log",
      "message": "Failed logon for user 'guest'",
      "severity": "medium",
      "event_time": "2026-08-01T10:15:00",
      "raw_data": { "status": "failed", "username": "guest" }
    }
  ]
}
```
`log_type` must be one of: `login`, `process`, `network`, `security`, `system`.
`severity` must be one of: `info`, `low`, `medium`, `high`, `critical`.

Response includes per-item acceptance so a single malformed entry never
rejects the whole batch:
```json
{ "status": "ok", "endpoint_id": 1, "accepted": 4, "rejected": [] }
```

#### `POST /api/agent/file-check`
Submits a file's SHA-256 hash for an optional VirusTotal lookup.

### Dashboard-session endpoints (require an active login + CSRF token)

| Method | Path | Role required | Purpose |
|--------|------|----------------|---------|
| GET | `/api/stats/summary` | any | Stat-card totals |
| GET | `/api/stats/security-score` | any | Security Score gauge + factor breakdown |
| GET | `/api/stats/top-threats` | any | Most frequently-triggered rules |
| GET | `/api/stats/attack-timeline` | any | Alerts/hour by severity, 24h |
| GET | `/api/stats/mitre-heatmap` | any | Real ATT&CK hit counts for the Heatmap page |
| GET | `/api/logs` | any | Paginated/filterable log list (`endpoint_id`, `log_type`, `severity`, `search`) |
| GET | `/api/hunt/search?q=...` | any | Threat Hunting field:value query engine |
| GET/POST/DELETE | `/api/hunt/saved` | any | Saved search list/create/delete |
| GET | `/api/endpoints`, `/api/endpoints/<id>` | any | Endpoint list + detail (includes live `risk_score`) |
| GET | `/api/alerts` | any | Filterable alert list (`status`, `severity`, `endpoint_id`) |
| POST | `/api/alerts/<id>/acknowledge` \| `/escalate` \| `/close` \| `/reopen` | analyst+ | Full status-flow transitions |
| POST | `/api/alerts/<id>/assign`, `/unassign` | analyst+ | Assignment |
| GET/POST | `/api/alerts/<id>/notes`, `/evidence` | any / analyst+ | Investigation notes & evidence |
| GET | `/api/alerts/<id>/timeline`, `/evidence-logs`, `/summary`, `/mitre-description` | any | Computed timeline, time-windowed related logs, Incident Summary, MITRE description |
| GET | `/api/cases`, `/api/cases/<id>` | any | List / detail correlated cases |
| POST | `/api/cases/<id>/status` | analyst+ | Transition open→investigating→resolved |
| — | `/api/cases/<id>/assign`, `/notes`, `/evidence`, `/timeline` | analyst+ / any | Same investigation workflow, applied to cases |
| GET | `/api/detection/rules` | any | List registered detection rule names |
| GET/POST/DELETE | `/api/detection/suppressions` | admin | Detection tuning |
| GET | `/api/agents/next-id` | admin | Reserve a guaranteed-unique Agent ID for provisioning |

---

## 🧠 Detection Engine

### Rules

| Rule | Trigger | Default Severity | MITRE ATT&CK |
|------|---------|-------------------|---------------|
| `multiple_failed_logins` | ≥ 5 failed logins for one endpoint within 10 minutes | High | T1110 — Brute Force |
| `suspicious_powershell` | PowerShell process with obfuscation/download flags (`-enc`, `-nop`, `downloadstring`, etc.) | Critical | T1059.001 — PowerShell |
| `new_admin_account` | Windows event 4732/4728/4756 or admin-group text match | Critical | T1098 — Account Manipulation |
| `port_scan_detection` | One remote IP hits ≥ 15 distinct local ports within 2 minutes | Medium | T1046 — Network Service Discovery |
| `blacklisted_ip_detection` | Network connection to/from an IP in `database/blacklisted_ips.txt` | High | T1071 — Application Layer Protocol |
| `malware_file_detection` | VirusTotal reports ≥ 1 engine flags a submitted file hash as malicious | Critical | T1027 — Obfuscated Files or Information |

All thresholds are configurable in `config.py`. Each rule has a real
one-line MITRE technique description shown in the alert detail page's
MITRE panel and on the ATT&CK Heatmap. These rules apply to both Windows
and Linux agents — the Windows-specific ones (PowerShell, admin-group-change)
simply won't fire on Linux, which is correct behavior, not a bug.

### Pipeline

```
Agent submits log
   → normalize_log()        common fields extracted (user, src_ip, dest_ip, process, file_hash)
                             -> stored in logs.normalized, queryable via the Threat Hunting page
   → for each rule:
        is_suppressed()?     admin-tunable, skip if silenced
        rule fires           → get_mitre_info() + compute_alert_risk_score()
        → create_alert()     → correlate_alert()   groups with other recent alerts on
                                                     the same endpoint into a Case,
                                                     refreshes the endpoint's aggregate risk_score
```

### Risk Scoring
Base score by severity (low=20, medium=45, high=70, critical=90), boosted
up to +20 for repeated alerts on the same endpoint within 30 minutes,
capped at 100. Both alert-level and endpoint-level risk recompute live —
escalating an alert raises it, closing alerts lowers it back down.

### Alert Investigation Workflow
Full status flow: `Open → Acknowledged → (Escalate) → In Progress → Closed → (Reopen) → Open`.
Escalating bumps severity one level (capped at critical) and recomputes
risk scores. Every transition is picked up automatically by the computed
investigation timeline (no separate event-log table to keep in sync) at
`/alerts/<id>`, alongside notes, evidence, and time-windowed related logs
from the same endpoint (the Evidence panel).

### Correlation
If an endpoint has 2+ related open alerts within 30 minutes, they're
automatically grouped into a **Case** — visible on the Cases page with an
aggregated severity/risk score and a per-case investigation workflow.

### Suppression
Admins can silence a specific rule — globally or scoped to one endpoint,
with an optional expiry — via the Detection Tuning API. A suppressed rule
never creates an alert at all.

---

## 🎯 MITRE ATT&CK Heatmap

`/heatmap` renders all 14 standard ATT&CK tactics as columns (matching
the familiar ATT&CK Navigator layout), with SecureWatch's actual mapped
techniques as cells beneath. Cell color reflects real hit count and
severity — **never fabricated coverage**: a technique this build can't
yet detect shows as an honest gray "not detected" cell, not a colored one.

---

## 🔎 Threat Hunting

`/hunt` lets an analyst run ad-hoc `field:value` queries against every
collected log, not just severity/type/agent filters. Supported fields:
`log_type`, `severity`, `source`, `agent_id`, `hostname` (direct columns),
`user`, `src_ip`, `dest_ip`, `process`, `file_hash`, `event_id`
(normalized fields, via SQLite's JSON1 extension against `logs.normalized`
— populated on every log since the detection engine's Phase 2, but never
actually queryable until this page existed), and a bare term or
`message:"..."` for free-text search. Example: `log_type:login
user:svc_admin` finds every login event for one account across every
agent. Frequent queries can be saved and are visible to the whole team.

---

## 🌐 Multi-Agent Architecture

```
Windows Agent (Agent-01) ─┐
Kali/Linux Agent (Agent-02) ─┤
Agent-03 ──────────────────┼──> SecureWatch Server → SQLite → Dashboard
Agent-04 ──────────────────┤
Agent-05 ──────────────────┘
```

- Every agent has a stable **Agent ID**, independent of hostname — safe
  even if two VMs share a hostname. The **Agents page** generates and
  reserves one for you (15-minute reservation, prevents two admins/tabs
  ever being handed the same suggestion).
- The Windows agent collects real Security event log data (via `pywin32`);
  the Linux agent parses real `/var/log/auth.log`/`/var/log/secure` entries
  (SSH attempts, `sudo` usage) — no synthetic/fake data anywhere.
- Process, network, and heartbeat collection (via `psutil`) work identically
  on both platforms.
- Each endpoint has its own detail page (`/endpoints/<id>`) showing only
  its own logs and alerts, plus a live risk score. Live Logs, Alerts,
  Cases, and Hunt all support filtering/searching by Agent.
- `last_seen_at` drives automatic 🟢 online / 🔴 offline status (5-minute
  threshold) — an agent that reconnects is marked online again automatically.

---

## 🎨 UI Theme

A dark, glassmorphism SOC console:
- Persistent left sidebar (collapses to a CSS-only mobile drawer) + slim topbar
- Translucent, blurred cards (`backdrop-filter`) with gradient borders and hover glow
- **IBM Plex Mono** for headers/data/labels (a "terminal" feel), **Inter** for body copy
- Animated stat cards, gradient-filled charts, toast notifications on every action
- Consistent severity colors across badges, charts, and incident lists:
  Low (blue), Medium (amber), High (orange), Critical (red)
- A live-scrolling event ticker across the top of every authenticated page

---

## 📸 Screenshots

Add your own screenshots to the `screenshots/` folder and reference them here:

- `screenshots/login.png` — Login page
- `screenshots/dashboard.png` — Main SOC dashboard
- `screenshots/logs.png` — Live log viewer
- `screenshots/hunt.png` — Threat Hunting page
- `screenshots/alert-detail.png` — Full-page alert investigation workflow
- `screenshots/heatmap.png` — MITRE ATT&CK Heatmap
- `screenshots/agents.png` — Agent provisioning page
- `screenshots/cases.png` — Correlated cases
- `screenshots/endpoints.png` — Multi-agent endpoint status + detail page

*(Placeholder — capture these after running the app locally.)*

---

## 🛠️ Troubleshooting

- **"Database not found" on startup** → run `python database/init_db.py` first.
- **Upgrading from an older version and something looks missing** → run
  `python database/migrate.py` — it's safe to run repeatedly and never
  touches existing data (including rebuilding the endpoints table
  structure in place if you're on a very old version).
- **Agent gets 401 Unauthorized** → the `--api-key` passed to the agent
  must exactly match `AGENT_API_KEY` in the server's `.env`/`config.py`.
- **Agent checkin returns 400 "already registered to a different
  endpoint"** → the `--agent-id` you chose is already used by a genuinely
  different machine (different hostname AND IP). Use the Agents page to
  get a guaranteed-free one instead of guessing.
- **No login/security events from the Windows agent** → install `pywin32`
  (`pip install pywin32`) and run with sufficient privileges to read the
  Security event log (often requires an elevated/Administrator terminal).
- **No login/security events from the Linux agent** → run with `sudo`, or
  add the user to the `adm` group. The agent prints a `[WARN]` at startup
  if the auth log isn't readable.
- **Ran the Linux agent but see no SSH/sudo events** → the agent only
  reports NEW log lines from the moment it starts (tail -f style). Generate
  a real event (e.g. `ssh baduser@localhost`, or any `sudo` command) *after*
  starting the agent.
- **Threat Hunting says "Unknown search field"** → check the field name
  against the list in the Threat Hunting section above - it's a
  deliberate error rather than a silently-ignored typo.
- **VirusTotal checks always show "not configured"** → set `VT_API_KEY`
  in `.env`. This is optional — the rest of the SIEM works without it.
- **A viewer/analyst gets 403 on an action** → that's RBAC working as
  intended — check the roles table above for what each role can do.

---

## 📚 Tech Stack

- **Backend:** Python, Flask, Flask-CORS, Flask-WTF (CSRF), Flask-Limiter (rate limiting)
- **Database:** SQLite (via Python's built-in `sqlite3`, including the JSON1 extension for Threat Hunting)
- **Frontend:** HTML5, CSS3 (glassmorphism), vanilla JavaScript, Bootstrap 5, Chart.js
- **Agent:** Python, psutil, requests, pywin32 (Windows, optional)
- **Threat Intelligence:** VirusTotal API v3 (optional)

---

## 📄 License

This project was created for academic purposes as a cybersecurity minor
project. Feel free to adapt it for coursework, demos, or further learning.
