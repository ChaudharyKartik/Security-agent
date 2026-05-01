# VAPT Platform — Setup & Run Guide

## Project Structure

```
security-agent/
├── main.py                  ← FastAPI REST API (entry point)
├── orchestrator.py          ← Pipeline orchestrator (parallel scan runner)
├── scan_config.py           ← ScanConfig dataclass (credentials, options)
├── enrichment.py            ← CVSS v3.1 scoring + finding enrichment
├── cvss.py                  ← CVSS calculator
├── validator.py             ← Human validation logic
├── report_generator.py      ← PDF + JSON report generation
├── requirements.txt
├── Dockerfile               ← Container image (API + UI + tools)
├── docker-compose.yml       ← One-command stack: api + ui + zap
├── .dockerignore
│
├── agents/
│   ├── knowledge_agent.py   ← Resolves WSTG checklist → execution plan
│   ├── fp_agent.py          ← AI false-positive analysis (LLM-powered)
│   ├── reviewer_agent.py    ← Human review queue + analyst decision engine
│   └── llm_client.py        ← Multi-provider LLM client (Groq/Gemini/OpenRouter/Ollama)
│
├── modules/
│   ├── recon.py             ← DNS, banner grab, port pre-scan
│   ├── network_module.py    ← Nmap wrapper (real + mock fallback)
│   ├── web_module.py        ← ZAP + Nuclei concurrent scan (built-in probes fallback)
│   └── cloud_module.py      ← Prowler wrapper (real + mock fallback)
│
├── checklist/
│   ├── WSTG_Checklist_v4.1.json  ← Source checklist (OWASP WSTG v4.1, 94 tests)
│   └── registry.json             ← Compiled registry (101 items: 94 web + 7 network/cloud)
│
├── database/
│   ├── models.py            ← SQLAlchemy ORM models
│   ├── crud.py              ← All DB read/write operations
│   └── connection.py        ← DB engine + session factory
│
├── ui/
│   └── app.py               ← Streamlit dashboard
│
├── reports/                 ← Auto-created. Stores PDF + JSON reports
└── vapt.db                  ← SQLite database (auto-created on first run)
```

---

## Option A — Docker Compose (recommended)

Single command starts everything: ZAP, FastAPI backend, and Streamlit UI.

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Docker Desktop | https://docs.docker.com/get-docker/ |
| Docker Compose v2 | Bundled with Docker Desktop |

### Step 1 — Create `.env`

```bash
# ── LLM provider (AI false-positive analysis) ─────────────
LLM_PROVIDER=groq          # groq | gemini | openrouter | ollama | none

GROQ_API_KEY=your_groq_api_key
# GEMINI_API_KEY=your_gemini_api_key
# OPENROUTER_API_KEY=your_openrouter_api_key

# ── Database (optional — SQLite used by default) ──────────
# DATABASE_URL=postgresql://user:password@localhost:5432/vapt
```

> `ZAP_API_BASE` and `API_BASE` are set automatically by docker-compose.yml — do not add them to `.env`.

### Step 2 — Build and start

```bash
docker compose up --build
```

First build takes 3–5 minutes (downloads Nuclei templates). Subsequent starts are fast.

| Service | URL |
|---------|-----|
| Streamlit UI | http://localhost:8501 |
| FastAPI API | http://localhost:8000 |
| ZAP daemon | http://localhost:8090 (internal to stack) |

### Useful compose commands

```bash
docker compose up -d          # run in background
docker compose logs -f api    # stream API logs
docker compose logs -f zap    # stream ZAP logs
docker compose down           # stop all services
docker compose down -v        # stop + delete DB volume (full reset)
```

> ZAP takes ~60 seconds to become healthy. The API waits for it before starting.

---

## Option B — Local / Manual Setup

Use this when you want to develop or debug without Docker.

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Required |
| Nmap | 7.x+ | Optional — mock fallback if absent |
| Nuclei | 3.x+ | Optional — ZAP probes used if absent |
| OWASP ZAP | 2.14+ | Optional — built-in HTTP probes if absent |
| Prowler | 5.x+ | Optional — mock cloud findings if absent |

### Step 1 — Virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### Step 2 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3 — Install scanning tools

#### Nmap

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows — download installer from https://nmap.org/download.html
nmap --version
```

#### Nuclei

```bash
# Linux / macOS
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Windows — download from https://github.com/projectdiscovery/nuclei/releases
nuclei -version
```

#### OWASP ZAP

Start ZAP in daemon mode (required only for local runs — Docker Compose handles this automatically):

```bash
# Windows
zap.bat -daemon -port 8090 -config api.key=changeme

# Linux / macOS
./zap.sh -daemon -port 8090 -config api.key=changeme
```

#### Prowler (cloud scans only)

Installed via `pip install -r requirements.txt`. Configure AWS credentials before running cloud scans:

```bash
aws configure
# or set: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
```

### Step 4 — Configure environment variables

Create a `.env` file in the project root:

```bash
# ── ZAP ──────────────────────────────────────────────────
ZAP_API_BASE=http://localhost:8090
ZAP_API_KEY=changeme

# ── LLM provider ─────────────────────────────────────────
LLM_PROVIDER=groq          # groq | gemini | openrouter | ollama | none

GROQ_API_KEY=your_groq_api_key
# GEMINI_API_KEY=your_gemini_api_key
# OPENROUTER_API_KEY=your_openrouter_api_key
# OLLAMA_MODEL=gemma3:4b   # if using local Ollama

# ── Database (optional) ───────────────────────────────────
# DATABASE_URL=postgresql://user:password@localhost:5432/vapt
```

> Get a free Groq API key at https://console.groq.com — no credit card required.

### Step 5 — Start the API

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Step 6 — Start the UI

Open a second terminal (with venv active):

```bash
streamlit run ui/app.py --server.port 8501
```

Open: **http://localhost:8501**

---

## Running your first scan

### Via the UI

1. Open http://localhost:8501
2. Click **New Scan** in the sidebar
3. Enter a target URL (e.g. `https://testphp.vulnweb.com`)
4. Choose scan mode: `full` (all 101 tests) or `checklist` (pick specific WSTG tests)
5. Click **Launch Scan**
6. Watch the progress — phases: Recon → Knowledge Resolution → Scanning → Enrichment → AI Analysis → Awaiting Validation
7. Go to **Review Queue** to confirm, reject, downgrade, or escalate findings
8. Go to **Generate Report** to export PDF or JSON

### Via the API

```bash
# Start a full web scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://testphp.vulnweb.com", "scan_mode": "full"}'

# Returns: {"session_id": "abc123", "status": "running"}

# Poll status
curl http://localhost:8000/session/abc123/status

# Get results
curl http://localhost:8000/session/abc123

# Get review queue
curl http://localhost:8000/session/abc123/review/queue

# Submit analyst decisions
curl -X POST http://localhost:8000/session/abc123/review \
  -H "Content-Type: application/json" \
  -d '{
    "decisions": [
      {"finding_id": "FIND-XXXX", "action": "confirm", "analyst": "Kartik"},
      {"finding_id": "FIND-YYYY", "action": "false_positive", "analyst": "Kartik", "notes": "Internal IP"}
    ],
    "analyst": "Kartik"
  }'

# Download PDF report
curl "http://localhost:8000/report/abc123/download?format=pdf" -o report.pdf

# Enable cloud scan (requires AWS credentials)
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "my-aws-account", "scan_mode": "full", "run_cloud": true}'
```

---

## Scan Modes

| Mode | Description |
|------|-------------|
| `full` | All 101 checklist tests applicable to the target |
| `checklist` | Only the tests you specify by name or WSTG ID |
| `single` | Exactly one test |
| `owasp` | OWASP standard coverage for the detected domain |

### Checklist mode example

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scan_mode": "checklist",
    "requested_tests": ["WSTG-INPV-05", "WSTG-SESS-05", "Testing for Clickjacking"]
  }'
```

---

## LLM Provider Configuration

The platform uses LLMs for AI false-positive analysis. Providers are tried in order until one succeeds:

**Fallback chain:** Groq → Gemini → OpenRouter → Ollama

| Provider | Env var | Free tier |
|----------|---------|-----------|
| Groq (default) | `GROQ_API_KEY` | Yes — https://console.groq.com |
| Gemini | `GEMINI_API_KEY` | Yes — https://aistudio.google.com |
| OpenRouter | `OPENROUTER_API_KEY` | Yes (limited) |
| Ollama | `OLLAMA_MODEL` | Local, no key needed |

Set `LLM_PROVIDER=none` to disable AI analysis entirely.

---

## Architecture Overview

```
POST /scan
    │
    └── Background Task
          │
          ├── 1. Recon           DNS · port pre-scan · host classification
          │
          ├── 2. Knowledge Agent  WSTG registry → execution plan (101 tests)
          │
          └── 3. ThreadPoolExecutor (parallel)
                  ├── Network Agent  →  Nmap (or mock)
                  ├── Web Agent      →  ZAP + Nuclei concurrent (or built-in probes)
                  └── Cloud Agent    →  Prowler (or mock, if run_cloud=True)
                          │
                          ├── 4. Enrichment    CVSS v3.1 scoring · deduplication
                          │
                          ├── 5. AI Analysis   False-positive detection (LLM)
                          │
                          ├── 6. Review Queue  Triage → analyst decisions
                          │
                          └── 7. DB Persist    SQLite / PostgreSQL
```

---

## Legal Practice Targets

Only scan targets you own or have written permission to test.

| Target | Type |
|--------|------|
| `https://testphp.vulnweb.com` | Vulnerable PHP app (Acunetix, intentional) |
| `https://juice-shop.herokuapp.com` | OWASP Juice Shop |
| `http://scanme.nmap.org` | Nmap's official scan-me host |
| Local VMs / lab environments | Best for network scanning |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `uvicorn: command not found` | Activate venv: `venv\Scripts\activate` |
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| Streamlit shows "API Offline" | Start FastAPI first on port 8000 |
| ZAP not detected (local run) | Start ZAP daemon on port 8090 with key `changeme` |
| Docker: ZAP healthcheck failing | Wait 60–90s; run `docker compose logs zap` to check |
| Nmap needs root (Linux) | `sudo uvicorn main:app --reload` or use mock mode |
| Prowler returns mock findings | Set AWS credentials (`aws configure`) and pass `run_cloud: true` |
| AI analysis skipped | Check `LLM_PROVIDER` + matching API key in `.env` |
| Port conflict | Change port in compose or pass `--port` to uvicorn/streamlit |
| DB errors on startup | Delete `vapt.db` (local) or `docker compose down -v` (Docker) to reset |
