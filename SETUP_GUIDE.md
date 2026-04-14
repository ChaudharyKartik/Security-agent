# AI Security Testing Agent — Phase 1 Setup & Run Guide

## Project Structure

```
security-agent/
├── main.py                  ← FastAPI entry point (REST API)
├── orchestrator.py          ← Orchestrator agent (parallel runner)
├── enrichment.py            ← CVSS enrichment + analyst notes
├── validator.py             ← Human validation logic
├── report_generator.py      ← JSON + HTML report output
├── requirements.txt         ← Python dependencies
├── modules/
│   ├── __init__.py
│   ├── recon.py             ← Recon agent (DNS, banner grab, port pre-check)
│   ├── network_module.py    ← Network agent (Nmap + CVE correlation)
│   ├── web_module.py        ← Web agent (ZAP API + built-in HTTP probes)
│   └── cloud_module.py      ← Cloud agent (Prowler + mock findings)
├── ui/
│   └── app.py               ← Streamlit dashboard
└── reports/                 ← Auto-created. Stores JSON + HTML reports
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python      | 3.11+   | Required |
| pip         | latest  | `pip install --upgrade pip` |
| Nmap        | 7.x+    | Optional — mock fallback if absent |
| OWASP ZAP   | 2.14+   | Optional — built-in probes if absent |
| Prowler     | 3.x+    | Optional — mock findings if absent |

---

## Step 1 — Clone / copy the project

If you received the project as a zip, extract it:
```bash
cd ~
unzip security-agent.zip      # or wherever you placed the files
cd security-agent
```

---

## Step 2 — Create and activate a virtual environment

```bash
# Create venv
python3 -m venv venv

# Activate (Linux / macOS)
source venv/bin/activate

# Activate (Windows PowerShell)
venv\Scripts\Activate.ps1
```

---

## Step 3 — Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

> All core features work with just these packages.  
> Nmap, ZAP, and Prowler integrations are detected automatically at runtime — the system falls back to mock/built-in data when they are absent.

---

## Step 4 — (Optional) Install real scanning tools

### Nmap
```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS (Homebrew)
brew install nmap

# Verify
nmap --version
```

After installing Nmap, also install the Python binding:
```bash
pip install python-nmap
```

### OWASP ZAP
1. Download from https://www.zaproxy.org/download/
2. Start ZAP in daemon mode:
```bash
# Linux
./zap.sh -daemon -port 8090 -config api.key=changeme

# Windows
zap.bat -daemon -port 8090 -config api.key=changeme
```
3. The web module will auto-detect ZAP at `http://localhost:8090`.  
   Change `ZAP_API_KEY` in `modules/web_module.py` if you use a different key.

### Prowler (AWS/GCP/Azure cloud checks)
```bash
pip install prowler

# Configure AWS credentials before running cloud scans
aws configure
```

---

## Step 5 — Start the FastAPI backend

```bash
# From the security-agent/ directory with venv active
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

Test it's alive:
```bash
curl http://localhost:8000/health
# Expected: {"status":"healthy","sessions_active":0}
```

Interactive API docs:
```
http://localhost:8000/docs      ← Swagger UI (try all endpoints)
http://localhost:8000/redoc     ← ReDoc
```

---

## Step 6 — Start the Streamlit UI

Open a **second terminal** (with venv active):

```bash
cd security-agent
source venv/bin/activate

streamlit run ui/app.py --server.port 8501
```

Open your browser at: **http://localhost:8501**

---

## Step 7 — Run your first scan

### Via the Streamlit UI

1. Open http://localhost:8501
2. Click **"🎯 New Scan"** in the sidebar
3. Enter a target (e.g. `https://testphp.vulnweb.com` for a legal practice target)
4. Click **"🚀 Launch Scan"**
5. Watch the live progress bar — phases: Recon → Scanning (parallel) → Enrichment
6. When complete, go to **"✅ Validate Findings"** to review and approve/reject
7. Go to **"📄 Generate Report"** to export JSON or HTML

### Via the API directly

```bash
# Start a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://testphp.vulnweb.com","run_cloud":false}'

# Poll status (replace SESSION_ID)
curl http://localhost:8000/session/SESSION_ID/status

# List all sessions
curl http://localhost:8000/sessions

# Validate a finding
curl -X POST http://localhost:8000/validate/SESSION_ID \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"FIND-ABCD1234","action":"approve","validator_name":"Kartik","notes":"Confirmed"}'

# Generate HTML report
curl "http://localhost:8000/report/SESSION_ID?format=html"
```

---

## Legal Practice Targets

Always test on authorized targets only. These are publicly available legal practice environments:

| Target | Type |
|--------|------|
| `https://testphp.vulnweb.com` | Intentionally vulnerable PHP app (Acunetix) |
| `https://juice-shop.herokuapp.com` | OWASP Juice Shop |
| `http://hackthissite.org` | Sanctioned CTF environment |
| Your own local VMs / lab | Preferred for network scanning |

For authorized VAPT engagements, always ensure written permission is in scope before running.

---

## Environment Variables (Optional)

Create a `.env` file in `security-agent/` to override defaults:

```bash
ZAP_API_BASE=http://localhost:8090
ZAP_API_KEY=changeme
```

> Note: Currently these are set as constants in `modules/web_module.py`.  
> Phase 2 will move all config to environment variables + `.env` loading.

---

## Architecture: How Parallel Scanning Works

```
User → POST /scan
         │
         └── Background Task
               │
               ├── 1. Recon Agent (sequential, feeds decision engine)
               │       DNS → port pre-scan → classify host type
               │
               └── 2. ThreadPoolExecutor (max_workers=3)
                       ├── Network Agent  ← Nmap / mock
                       ├── Web Agent      ← ZAP / HTTP probes
                       └── Cloud Agent    ← Prowler / mock (if enabled)
                               │
                               └── Enrichment (CVSS, analyst notes, dedup)
                                       │
                                       └── Status → "awaiting_validation"
```

Web, Network, and Cloud agents run **simultaneously** in separate threads.  
The Orchestrator waits for all three, then enriches the combined results.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `uvicorn: command not found` | Activate venv: `source venv/bin/activate` |
| `ModuleNotFoundError: httpx` | Run `pip install -r requirements.txt` |
| Streamlit shows "API Offline" | Start FastAPI first: `uvicorn main:app --reload` |
| ZAP not detected | ZAP daemon must be running on port 8090 with correct API key |
| Nmap requires root (Linux) | Run: `sudo uvicorn main:app --reload` or use mock mode |
| `python-nmap not installed` | `pip install python-nmap` — mock fallback is used automatically |
| Port 8000 in use | `uvicorn main:app --port 8001 --reload` and update `API_BASE` in `ui/app.py` |

---

## Running Tests

A quick smoke test to verify everything is wired up:

```bash
# 1. Start the API
uvicorn main:app --reload &

# 2. Wait 2 seconds, then run a test scan
sleep 2
curl -s -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://testphp.vulnweb.com"}' | python3 -m json.tool

# 3. List sessions to confirm
curl -s http://localhost:8000/sessions | python3 -m json.tool
```

---

## What's Next — Phase 2 Preview

Phase 1 is your production-ready foundation. Phase 2 adds:

- **LLM reasoning** (Claude API) in the Orchestrator for intelligent module selection and finding narratives
- **Celery + Redis** job queue replacing FastAPI background tasks (enables true multi-scan concurrency)
- **PostgreSQL** persistence replacing in-memory `sessions: dict`
- **React/Next.js** dashboard with WebSocket live feed replacing Streamlit
- **PDF + DOCX** report export
- **CVSS v4.0** support
- **Retest agent** — auto-schedules follow-up scans after remediation deadlines
- **CVE intelligence feed** — NVD/OSV sync to correlate live CVEs against detected software versions
