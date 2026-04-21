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
│
├── agents/
│   ├── knowledge_agent.py   ← Resolves WSTG checklist → execution plan
│   ├── fp_agent.py          ← AI false-positive analysis (LLM-powered)
│   └── llm_client.py        ← Multi-provider LLM client (Groq/Gemini/Ollama)
│
├── modules/
│   ├── recon.py             ← DNS, banner grab, port pre-scan
│   ├── network_module.py    ← Nmap wrapper (real + mock fallback)
│   ├── web_module.py        ← OWASP ZAP wrapper (real + built-in probes)
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

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Required |
| Nmap | 7.x+ | Optional — mock fallback if absent |
| OWASP ZAP | 2.14+ | Optional — built-in HTTP probes if absent |
| Prowler | 5.x+ | Optional — mock cloud findings if absent |

---

## Step 1 — Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

---

## Step 2 — Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Step 3 — Install scanning tools

### Nmap

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows — download installer from https://nmap.org/download.html
# Verify:
nmap --version
```

### OWASP ZAP

1. Download from https://www.zaproxy.org/download/
2. Start ZAP in daemon mode:

```bash
# Windows
zap.bat -daemon -port 8090 -config api.key=changeme

# Linux / macOS
./zap.sh -daemon -port 8090 -config api.key=changeme
```

ZAP runs on `http://localhost:8090` by default. The web module auto-detects it there.

### Prowler (cloud scans only)

Prowler is installed automatically with `pip install -r requirements.txt` since it is listed as a Python package. No extra installation needed.

Configure AWS credentials before running cloud scans:

```bash
aws configure
# or set environment variables:
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
```

---

## Step 4 — Configure environment variables

Create a `.env` file in the project root (or set these in your shell):

```bash
# ── ZAP ──────────────────────────────────────────────
ZAP_API_BASE=http://localhost:8090
ZAP_API_KEY=changeme

# ── AI False-Positive Analysis (pick one provider) ───
LLM_PROVIDER=groq          # groq | gemini | openrouter | ollama | none

# Groq (free tier, fastest — recommended)
GROQ_API_KEY=your_groq_api_key

# Gemini (free tier)
# LLM_PROVIDER=gemini
# GEMINI_API_KEY=your_gemini_api_key

# OpenRouter
# LLM_PROVIDER=openrouter
# OPENROUTER_API_KEY=your_openrouter_api_key

# Local Ollama (no API key needed, slowest)
# LLM_PROVIDER=ollama
# OLLAMA_MODEL=gemma3:4b

# Disable AI analysis entirely
# LLM_PROVIDER=none

# ── Database ─────────────────────────────────────────
# Default: SQLite (vapt.db in project root) — no config needed
# PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost:5432/vapt
```

> Get a free Groq API key at https://console.groq.com — no credit card required.

---

## Step 5 — Start the FastAPI backend

```bash
# From project root with venv active
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Verify it's running:

```bash
curl http://localhost:8000/health
# {"status":"healthy","db":"ok","sessions_active":0}
```

API docs:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## Step 6 — Start the Streamlit UI

Open a second terminal (with venv active):

```bash
streamlit run ui/app.py --server.port 8501
```

Open: **http://localhost:8501**

---

## Step 7 — Run your first scan

### Via the UI

1. Open http://localhost:8501
2. Click **New Scan** in the sidebar
3. Enter a target URL (e.g. `https://testphp.vulnweb.com`)
4. Choose scan mode: `full` (all 101 tests) or `checklist` (pick specific WSTG tests)
5. Click **Launch Scan**
6. Watch the progress — phases: Recon → Knowledge Resolution → Scanning → Enrichment → AI Analysis
7. Go to **Validate Findings** to approve or reject findings
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

# Validate a finding
curl -X POST http://localhost:8000/validate/abc123 \
  -H "Content-Type: application/json" \
  -d '{"finding_id": "FIND-XXXX", "action": "approve", "validator_name": "Kartik"}'

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

## Architecture Overview

```
POST /scan
    │
    └── Background Task
          │
          ├── 1. Recon          DNS · port pre-scan · host classification
          │
          ├── 2. Knowledge Agent  WSTG registry → execution plan (101 tests)
          │
          └── 3. ThreadPoolExecutor (parallel)
                  ├── Network Agent  →  Nmap (or mock)
                  ├── Web Agent      →  OWASP ZAP (or built-in probes)
                  └── Cloud Agent    →  Prowler (or mock, if run_cloud=True)
                          │
                          ├── 4. Enrichment   CVSS v3.1 scoring · deduplication
                          │
                          ├── 5. AI Analysis  False-positive detection (LLM)
                          │
                          └── 6. DB Persist   SQLite / PostgreSQL
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
| ZAP not detected | Start ZAP daemon on port 8090 with key `changeme` |
| Nmap needs root (Linux) | `sudo uvicorn main:app --reload` or use mock mode |
| Prowler returns mock findings | Set AWS credentials (`aws configure`) and pass `run_cloud: true` |
| AI analysis skipped | Set `LLM_PROVIDER` + matching API key, or set `LLM_PROVIDER=none` to disable |
| Port 8000 in use | `uvicorn main:app --port 8001` and update `API_BASE` in `ui/app.py` |
| DB errors on startup | Delete `vapt.db` to reset (all scan history will be lost) |
