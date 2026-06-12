# AI VAPT Agent Platform

> LLM-driven Vulnerability Assessment & Penetration Testing — Recon → Web → Network → Cloud → Human Review → Report

---

## What This Is

An AI-driven VAPT platform where LLMs act as the security analyst. Python executes tool calls; the LLM decides what to test, what it means, and what to report.

- **ReAct agent loop** — each agent thinks, calls tools, observes results, repeats
- **Multi-agent parallel scans** — Web, Network, and Cloud agents run concurrently after Recon
- **Human-in-the-loop review** — Critical/High findings require analyst sign-off before the report finalises
- **LLM-generated reports** — narrative sections, attack surface summary, remediation roadmap
- **Persistent sessions** — SQLite (default) or PostgreSQL; survives server restarts
- **REST API + Streamlit UI** — full scan management, review queue, report export

---

## Architecture

```
POST /scan
    │
    └── Background Task
          │
          ├── 1. ReconAgent ── DNS · Nmap · TLS · Nuclei · single LLM analysis pass
          │         └── returns: ip_address, open_ports, host_type, technologies, findings
          │
          ├── 2. Domain inference + agent selection (web / network / cloud)
          │
          └── 3. ThreadPoolExecutor (parallel)
                  ├── WebAgent     →  ZAP + Nuclei + http_request (ReAct loop)
                  ├── NetworkAgent →  Nmap + search_cve (ReAct loop)
                  └── CloudAgent   →  Prowler (ReAct loop, opt-in via run_cloud=true)
                          │
                          ├── 4. Enrichment     CVSS v3.1 scoring · deduplication
                          │
                          ├── 5. ReviewerAgent  builds human review queue (Critical/High)
                          │
                          ├── 6. ReportAgent    draft narrative (Medium/Low/Info immediately)
                          │
                          └── 7. DB persist     SQLite / PostgreSQL
                                    │
                    Analyst works review queue (UI or API)
                                    │
                          ReportAgent.finalise() → merges decisions → final report
```

---

## Project Structure

```
security-agent/
├── main.py               ← FastAPI REST API v5
├── orchestrator.py       ← Sequences agents — no security logic
├── enrichment.py         ← CVSS v3.1 scoring + deduplication
├── report_generator.py   ← JSON / HTML / CSV / PDF export
├── scan_config.py        ← Auth + scan options model
├── validator.py          ← Analyst feedback (persisted to DB)
├── cvss.py               ← CVSS v3.1 calculator
├── requirements.txt
├── Dockerfile
├── docker-compose.yml    ← One-command stack: API + UI + ZAP
├── .env.example          ← Copy to .env and fill in keys
│
├── agents/
│   ├── base_agent.py     ← ReAct loop engine (THINK → TOOL CALL → OBSERVE)
│   ├── llm_client.py     ← Multi-provider LLM client (Groq / Gemini / Ollama)
│   ├── tool_registry.py  ← Tool schema registry for function calling
│   ├── agent_contract.py ← AgentInput / AgentOutput / Finding types
│   ├── recon_agent.py    ← Sequential pipeline: DNS → Nmap → TLS → Nuclei → LLM
│   ├── web_agent.py      ← LLM-driven: ZAP + Nuclei + HTTP probes
│   ├── network_agent.py  ← LLM-driven: Nmap + CVE search
│   ├── cloud_agent.py    ← LLM-driven: Prowler (AWS / GCP / Azure)
│   ├── reviewer_agent.py ← Builds review queue; applies analyst decisions
│   ├── report_agent.py   ← Draft narrative + finalise with analyst decisions
│   └── tools/
│       ├── http_tool.py      ← Scoped HTTP requests (replaces probes.py)
│       ├── nmap_tool.py
│       ├── nuclei_tool.py
│       ├── zap_tool.py
│       ├── prowler_tool.py
│       ├── dns_tool.py
│       ├── ssl_tool.py
│       ├── cve_tool.py
│       └── finding_tool.py
│
├── database/
│   ├── models.py         ← ORM: ScanSession, ScanFinding, AnalystFeedback, ScanReport
│   ├── crud.py           ← Data access layer
│   └── connection.py     ← Engine + session factory
│
├── checklist/
│   ├── WSTG_Checklist_v4.1.json  ← OWASP WSTG v4.1 reference (94 tests)
│   └── registry.json             ← Prompt reference for agents
│
├── ui/
│   └── app.py            ← Streamlit dashboard
│
└── reports/              ← Auto-created. Stores generated report files
```

---

## Quick Start

### Docker (recommended)

```bash
cp .env.example .env
# Edit .env — add your LLM API key

docker compose up --build
```

| Service | URL |
|---------|-----|
| Streamlit UI | http://localhost:8501 |
| FastAPI + Swagger | http://localhost:8000/docs |
| ZAP (internal) | http://localhost:8090 |

First build takes 3–5 minutes (downloads Nuclei templates). ZAP takes ~60s to become healthy.

### Manual

```bash
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux / macOS

pip install -r requirements.txt

cp .env.example .env
# Edit .env

uvicorn main:app --reload --host 0.0.0.0 --port 8000
# In a second terminal:
streamlit run ui/app.py --server.port 8501
```

---

## Running a Scan

### Via UI

1. Open **http://localhost:8501**
2. Enter target URL → choose scan mode → click **Launch Scan**
3. Watch live phase progress: Recon → Scanning → Enrichment → Awaiting Validation
4. Go to **Review Queue** → confirm, reject, downgrade, or escalate Critical/High findings
5. Go to **Report** → download PDF / HTML / JSON / CSV

### Via API

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

# Get review queue (Critical/High needing sign-off)
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

# Download report
curl "http://localhost:8000/report/A1B2C3D4/download?format=pdf" -o report.pdf
```

---

## Scan Modes

| Mode | Description |
|------|-------------|
| `full` | All applicable agents for the detected domain |
| `owasp` | Same as full — OWASP coverage is the agent's responsibility |
| `checklist` | Pass specific WSTG test IDs or names as focus hints to agents |
| `single` | Run exactly one agent with the requested test as its goal |

---

## Review Actions

| Action | Effect on report |
|--------|-----------------|
| `confirm` | Included at original severity |
| `false_positive` | Excluded entirely |
| `downgrade` | Included at `new_severity` |
| `escalate` | Included at escalated severity |
| `needs_retest` | Included with "unverified" flag |

---

## LLM Providers

Fallback chain: **Groq → Gemini → Ollama**

| Provider | Env var | Free tier |
|----------|---------|-----------|
| Groq (default) | `GROQ_API_KEY` | Yes — https://console.groq.com |
| Gemini | `GEMINI_API_KEY` | Yes — https://aistudio.google.com |
| Ollama | `OLLAMA_MODEL` | Local, no key needed |

Set `LLM_PROVIDER=none` to disable LLM analysis.

---

## Optional Tools

All tools have graceful fallbacks if absent.

| Tool | Used by | Install |
|------|---------|---------|
| Nmap 7.x+ | NetworkAgent, ReconAgent | https://nmap.org/download.html |
| Nuclei 3.x+ | WebAgent, ReconAgent | https://github.com/projectdiscovery/nuclei/releases |
| OWASP ZAP 2.14+ | WebAgent | https://www.zaproxy.org/download/ (or via Docker) |
| Prowler 5.x+ | CloudAgent | `pip install prowler` + AWS credentials |

---

## Authenticated Scans

Pass credentials in the scan request:

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

---

## Database

SQLite by default (`vapt.db`, auto-created). Switch to PostgreSQL:

```bash
DATABASE_URL=postgresql://user:pass@localhost/vapt
```

---

## Legal Notice

Only scan systems you own or have **written authorization** to test.

Safe practice targets: `https://testphp.vulnweb.com` · `http://scanme.nmap.org` · `https://juice-shop.herokuapp.com`
