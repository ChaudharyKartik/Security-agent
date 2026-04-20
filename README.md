# AI VAPT Agent Platform

> **Phase 2 Complete** — DB-persistent, confidence-scored, checklist-driven vulnerability assessment platform.

---

## What This Is

An AI-driven Vulnerability Assessment & Penetration Testing (VAPT) platform that:

- Runs **multi-agent parallel scans** (Recon → Web → Network → Cloud)
- Uses a **Knowledge Agent** to select which tests to run based on the target type
- **Persists all findings to SQLite** (PostgreSQL-ready) — survives server restarts
- Assigns a **confidence score (0.0–1.0)** to every finding using heuristic evidence analysis
- Provides a **REST API** (FastAPI) and **Streamlit dashboard** for scan management and review

---

## Project Structure

```
security-agent/
├── main.py                  ← FastAPI REST API (v4 — DB-backed)
├── orchestrator.py          ← Scan coordination & agent dispatch
├── enrichment.py            ← CVSS scoring + confidence scoring
├── validator.py             ← Analyst feedback (persisted to DB)
├── report_generator.py      ← JSON / HTML / CSV report export
├── scan_config.py           ← Auth & scan configuration model
├── cvss.py                  ← CVSS v3.1 calculator
├── requirements.txt
│
├── agents/
│   ├── knowledge_agent.py   ← Resolves WHAT to test (checklist-driven)
│   └── agent_contract.py    ← AgentInput / AgentOutput / Finding contracts (Phase 3)
│
├── modules/                 ← Scanner modules (become agents in Phase 3)
│   ├── recon.py             ← DNS, HTTP banner, port pre-scan
│   ├── web_module.py        ← ZAP API + built-in HTTP probes
│   ├── network_module.py    ← Nmap + CVE correlation + default creds
│   └── cloud_module.py      ← Prowler (AWS/GCP/Azure) + mock fallback
│
├── database/
│   ├── connection.py        ← SQLAlchemy engine + session factory
│   ├── models.py            ← ORM: ScanSession, ScanFinding, AnalystFeedback, ScanReport
│   └── crud.py              ← Data access layer
│
├── checklist/
│   └── registry.json        ← 17-item canonical test registry (OWASP + NIST + CIS)
│
├── ui/
│   └── app.py               ← Streamlit dashboard
│
├── reports/                 ← Auto-generated scan reports
├── vapt.db                  ← SQLite database (auto-created)
└── PLAN.md                  ← Full project roadmap
```

---

## Quick Start

### 1 — Install dependencies

```powershell
# Create and activate venv (Windows)
python -m venv venv
venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### 2 — Start the API

```powershell
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3 — Start the UI (separate terminal)

```powershell
streamlit run ui/app.py --server.port 8501
```

### 4 — Open the dashboard

```
http://localhost:8501   ← Streamlit UI
http://localhost:8000/docs  ← Swagger API docs
```

---

## Running a Scan

### Via UI
1. Go to **Scan** tab → enter target → click **LAUNCH**
2. Watch live progress (Recon → Scanning → Enrichment)
3. Go to **Review** tab → select session → inspect findings
4. **Approve / Reject / Escalate** findings for audit trail
5. Go to **Export** tab → download report

### Via API

```bash
# Start scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://scanme.nmap.org","scan_mode":"full","run_cloud":false}'

# Poll status
curl http://localhost:8000/session/SESSION_ID/status

# Get findings (filter by confidence)
curl "http://localhost:8000/session/SESSION_ID/findings?min_confidence=0.4"

# Validate a finding
curl -X POST http://localhost:8000/validate/SESSION_ID \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"FIND-XXXX","action":"approve","validator_name":"Analyst"}'

# List all sessions (from DB)
curl http://localhost:8000/sessions
```

---

## Scan Modes

| Mode | What it does |
|------|-------------|
| `full` | All 17 checklist items — web + network + cloud (if enabled) |
| `checklist` | Only specified tests by name or ID |
| `single` | Exactly one test |
| `owasp` | OWASP/NIST standard coverage for the detected domain |

---

## Optional Tools (auto-detected, mock fallback if absent)

| Tool | Purpose | Install |
|------|---------|---------|
| Nmap 7.x+ | Port scanning + banner grab | `sudo apt install nmap && pip install python-nmap` |
| OWASP ZAP 2.14+ | Web vulnerability scanning | https://www.zaproxy.org/download/ — run on port 8090 |
| Prowler 3.x+ | AWS/GCP/Azure cloud checks | `pip install prowler` |

---

## Architecture

```
POST /scan
    │
    └── BackgroundTask (own DB session)
          │
          ├── 1. KnowledgeAgent.resolve() — picks tests based on target + mode
          │
          ├── 2. ReconAgent — DNS, HTTP banner, port pre-scan
          │
          └── 3. ThreadPoolExecutor (parallel)
                ├── WebAgent    ← ZAP or HTTP probes
                ├── NetworkAgent← Nmap + CVE correlation
                └── CloudAgent  ← Prowler / mock (only if run_cloud=True)
                      │
                      └── Enrichment (CVSS + confidence scoring)
                            │
                            └── DB write (ScanSession + ScanFindings)
```

---

## Database

SQLite by default (`vapt.db`). Switch to PostgreSQL by setting:

```bash
DATABASE_URL=postgresql://user:pass@localhost/vapt
```

Tables: `scan_sessions` · `scan_findings` · `analyst_feedback` · `scan_reports`

---

## Legal Notice

Only scan systems you own or have **written authorization** to test.
Safe practice targets: `http://scanme.nmap.org` · `https://testphp.vulnweb.com`
