# VAPT Platform — Setup Guide

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Required |
| Docker + Docker Compose | Latest | For Docker setup only |
| Nmap | 7.x+ | Optional — mock fallback if absent |
| Nuclei | 3.x+ | Optional — skipped if absent |
| OWASP ZAP | 2.14+ | Optional — built-in HTTP probes if absent |
| Prowler | 5.x+ | Optional — cloud scans only |

---

## Option A — Docker Compose (recommended)

Starts everything in one command: ZAP, FastAPI backend, Streamlit UI.

### Step 1 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` and add your LLM API key (minimum required):

```bash
LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key   # https://console.groq.com — free, no card
```

`ZAP_API_BASE` and API service URLs are set automatically by `docker-compose.yml` — do not add them.

### Step 2 — Build and start

```bash
docker compose up --build
```

First build takes 3–5 minutes (downloads Nuclei templates). Subsequent starts are fast.

| Service | URL |
|---------|-----|
| Streamlit UI | http://localhost:8501 |
| FastAPI + Swagger | http://localhost:8001/docs |
| ZAP daemon | http://localhost:8090 (internal to stack) |

The API's host-exposed port is `8001` (Docker Compose only — the container listens on `8000` internally, and the UI reaches it over Docker's internal network regardless). This is deployment-specific — pick whatever's actually free on your machine (check with `sudo ss -tlnp`) and change only the host side of the `api` service's `ports:` mapping in `docker-compose.yml` (`"8001:8000"` → `"<your-port>:8000"`) — leave the container-side `8000` and the internal `ZAP_API_BASE`/`API_BASE` values alone, they're unrelated to the host mapping.

ZAP takes ~60 seconds to become healthy. The API waits for it automatically.

### Useful compose commands

```bash
docker compose up -d           # run in background
docker compose logs -f api     # stream API logs
docker compose logs -f zap     # stream ZAP logs
docker compose down            # stop all services
docker compose down -v         # stop + delete DB volume (full reset)
```

---

## Option B — Local / Manual Setup

### Step 1 — Virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### Step 2 — Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3 — Configure environment

```bash
cp .env.example .env
```

Edit `.env`. Minimum required:

```bash
LLM_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key

ZAP_API_BASE=http://localhost:8090
ZAP_API_KEY=changeme
```

### Step 4 — Install scanning tools (optional but recommended)

#### Nmap

```bash
# Ubuntu / Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows — download from https://nmap.org/download.html
nmap --version
```

#### Nuclei

```bash
# Linux / macOS (requires Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Windows — download binary from https://github.com/projectdiscovery/nuclei/releases
nuclei -version
```

#### OWASP ZAP

Start ZAP in daemon mode before launching the API:

```bash
# Windows
zap.bat -daemon -port 8090 -config api.key=changeme

# Linux / macOS
./zap.sh -daemon -port 8090 -config api.key=changeme
```

#### Prowler (cloud scans only)

Prowler is included in `requirements.txt`. Configure AWS credentials before running cloud scans:

```bash
aws configure
# or set: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
```

### Step 5 — Start the API

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 6 — Start the UI (separate terminal, venv active)

```bash
streamlit run ui/app.py --server.port 8501
```

Open **http://localhost:8501**

---

## Running Your First Scan

### Via the UI

1. Open http://localhost:8501
2. Enter a target URL (e.g. `https://testphp.vulnweb.com`)
3. Choose scan mode — `full` for a complete scan
4. Click **Launch Scan**
5. Watch phase progress: Recon → Scanning → Enrichment → Awaiting Validation
6. Go to **Review Queue** — work through Critical/High findings (confirm / false_positive / downgrade / escalate / needs_retest)
7. Once all reviewed → **Generate Report** → download PDF / HTML / JSON / CSV

### Via the API

```bash
# Start a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://testphp.vulnweb.com", "scan_mode": "full"}'
# Returns: {"session_id": "A1B2C3D4", ...}

# Poll status
curl http://localhost:8000/session/A1B2C3D4/status

# Get findings
curl http://localhost:8000/session/A1B2C3D4/findings

# Filter findings by severity
curl "http://localhost:8000/session/A1B2C3D4/findings?severity=High"

# Get review queue
curl http://localhost:8000/session/A1B2C3D4/review/queue

# Submit analyst decisions
curl -X POST http://localhost:8000/session/A1B2C3D4/review \
  -H "Content-Type: application/json" \
  -d '{
    "decisions": [
      {"finding_id": "FIND-XXXX", "action": "confirm",        "analyst": "Kartik"},
      {"finding_id": "FIND-YYYY", "action": "false_positive", "analyst": "Kartik", "notes": "Internal IP"},
      {"finding_id": "FIND-ZZZZ", "action": "downgrade",      "analyst": "Kartik", "new_severity": "Medium"}
    ],
    "analyst": "Kartik"
  }'

# Generate and download report
curl "http://localhost:8000/report/A1B2C3D4/download?format=pdf" -o report.pdf

# List all sessions
curl http://localhost:8000/sessions

# Delete a session
curl -X DELETE http://localhost:8000/session/A1B2C3D4
```

---

## Scan Modes

| Mode | Description |
|------|-------------|
| `full` | All applicable agents for the detected target domain |
| `owasp` | Same as full (OWASP coverage is the agent's responsibility) |
| `checklist` | Pass specific WSTG test IDs or names as focus hints |
| `single` | Run exactly one agent with the test as its goal |

---

## Authenticated Scans

```json
{
  "target": "https://example.com",
  "scan_mode": "full",
  "auth_type": "token",
  "auth_token": "eyJhbGci...",
  "token_header": "Authorization",
  "token_prefix": "Bearer"
}
```

Auth types: `none` | `basic` | `token` | `cookie` | `api_key`

For API key auth:
```json
{
  "auth_type": "api_key",
  "api_key_name": "X-API-Key",
  "api_key_value": "your_key",
  "api_key_in": "header"
}
```

---

## Database

SQLite by default — `vapt.db` is auto-created on first run. Switch to PostgreSQL:

```bash
DATABASE_URL=postgresql://user:password@localhost:5432/vapt
```

To reset the database:
- Local: delete `vapt.db`
- Docker: `docker compose down -v`

### Upgrading an existing database

A brand-new database always has the current full schema — `init_db()` calls `Base.metadata.create_all()` at startup, which creates every table as defined right now. That call does **not**, however, add new columns to a table that already exists — so if you're pulling updates into a project that already has a `vapt.db` (or a PostgreSQL database) from before the `review_queue` column was added to `scan_sessions`, you need one manual step:

```bash
# SQLite
python -c "
import sqlite3
conn = sqlite3.connect('vapt.db')
cur = conn.cursor()
cur.execute(\"PRAGMA table_info(scan_sessions)\")
if 'review_queue' not in [r[1] for r in cur.fetchall()]:
    cur.execute('ALTER TABLE scan_sessions ADD COLUMN review_queue TEXT')
    conn.commit()
    print('Migrated.')
else:
    print('Already up to date.')
"
```

```sql
-- PostgreSQL
ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS review_queue TEXT;
```

This is additive and non-destructive — it only adds a new nullable column, no existing rows are touched. Without it, review-queue loads for sessions that already exist will keep falling back to an on-demand rebuild every time (functional, just slower and without persisted history — see `DOCUMENTATION.md` §3.6) instead of erroring outright.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `uvicorn: command not found` | Activate venv: `venv\Scripts\activate` |
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| Streamlit shows "API Offline" | Start FastAPI first on port 8000 |
| ZAP not detected (local run) | Start ZAP daemon on port 8090 with key `changeme` |
| Docker: ZAP healthcheck failing | Wait 60–90s — run `docker compose logs zap` |
| Nmap permission error (Linux) | `sudo uvicorn main:app --reload` |
| LLM analysis not running | Check `LLM_PROVIDER` + matching API key in `.env` |
| Ollama not responding | Check `ollama serve` is running; raise `OLLAMA_TIMEOUT` if slow |
| Port conflict | Change port: `uvicorn ... --port 8001` or edit `docker-compose.yml` |
| DB locked error on delete | Scan may still be active — wait and retry |
| Prowler returns no findings | Configure AWS credentials with `aws configure` |
| Review queue won't load / times out | First load for a session predating queue persistence makes a real LLM call per Critical/High finding to write its brief — this can legitimately take tens of seconds under free-tier rate limits. Retry once; it's persisted after the first successful load and is fast every time after. |
| Can't reach the UI/API from another device on the same network (`ERR_CONNECTION_TIMED_OUT`) | On Windows, this is almost always the firewall, not the server. Confirm the server is actually listening on `0.0.0.0` (not just `127.0.0.1`) with `netstat -ano \| findstr 8501` (or `8000`). If it is, check whether Windows has classified the network as **Public** (`Get-NetConnectionProfile` in PowerShell) — Public profiles block unsolicited inbound connections by default. Check for a conflicting rule for the *specific* `python.exe` your venv uses (`Get-NetFirewallRule -Direction Inbound \| Where DisplayName -eq 'python.exe'`) — a machine can easily have both an Allow rule for one Python install and a Block rule for another, and Block always wins when both exist for the same profile. Fix with a scoped inbound rule for the ports you actually need (not a blanket allow for the whole binary), e.g.: `New-NetFirewallRule -DisplayName "VAPT UI" -Direction Inbound -Protocol TCP -LocalPort 8501,8000 -Action Allow -Profile Public -RemoteAddress LocalSubnet` — the `-RemoteAddress LocalSubnet` scoping keeps this open to your own network only, not the whole internet. |
