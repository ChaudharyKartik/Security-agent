"""
FastAPI Entry Point — v3 (Knowledge Agent integrated)

New fields in ScanRequest:
  scan_mode:       full | checklist | single | owasp
  requested_tests: list of canonical test names for checklist/single modes

New endpoints:
  GET  /checklist            — list all available tests
  GET  /checklist/search     — search tests by name
  GET  /checklist/{id}       — get single test definition
  GET  /session/{id}/plan    — see the resolved execution plan for a session
"""
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator

from orchestrator import Orchestrator
from agents.knowledge_agent import KnowledgeAgent, MODE_FULL
from scan_config import ScanConfig
from validator import validate_finding, validate_batch, get_validation_stats
from report_generator import generate_report

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI VAPT Agent Platform",
    version="3.0.0",
    description="Knowledge Agent-driven VAPT. Checklist-first, OWASP fallback. Authorized use only.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

sessions: dict = {}
_ka = KnowledgeAgent()   # singleton — loaded once at startup


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:          str
    description:     Optional[str]  = None

    # Scan mode — this is new
    scan_mode:       str            = "full"    # full | checklist | single | owasp
    requested_tests: list[str]      = []        # e.g. ["SQL Injection", "XSS"]

    # Auth / credential config (all optional)
    auth_type:            Optional[str]  = "none"
    username:             Optional[str]  = None
    password:             Optional[str]  = None
    login_url:            Optional[str]  = None
    auth_token:           Optional[str]  = None
    token_header:         Optional[str]  = "Authorization"
    token_prefix:         Optional[str]  = "Bearer"
    session_cookie_name:  Optional[str]  = None
    session_cookie_value: Optional[str]  = None
    api_key_name:         Optional[str]  = None
    api_key_value:        Optional[str]  = None
    api_key_in:           Optional[str]  = "header"
    custom_headers:       Optional[dict] = None
    nmap_extra_args:      Optional[str]  = None
    nmap_ports:           Optional[str]  = None
    zap_api_key:          Optional[str]  = "changeme"
    zap_api_base:         Optional[str]  = "http://localhost:8090"
    aws_profile:          Optional[str]  = None
    aws_region:           Optional[str]  = "us-east-1"
    cloud_provider:       Optional[str]  = "aws"
    run_cloud:            bool           = False
    scan_depth:           Optional[str]  = "standard"

    @field_validator("target")
    @classmethod
    def not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Target cannot be empty")
        return v.strip()

    @field_validator("scan_mode")
    @classmethod
    def valid_mode(cls, v):
        valid = {"full", "checklist", "single", "owasp"}
        if v not in valid:
            raise ValueError(f"scan_mode must be one of: {valid}")
        return v

    def to_scan_config(self) -> ScanConfig:
        return ScanConfig(**{k: v for k, v in self.model_dump().items()
                             if k in ScanConfig.model_fields})


class ValidationRequest(BaseModel):
    finding_id:     str
    action:         str
    validator_name: str
    notes:          Optional[str] = None


class BatchValidationRequest(BaseModel):
    approved_ids:   list[str] = []
    rejected_ids:   list[str] = []
    validator_name: str


# ── Background scan task ───────────────────────────────────────────────────────

def _run_scan(session_id: str, target: str, config: ScanConfig,
              scan_mode: str, requested_tests: list):
    def _cb(sid, status):
        if sid in sessions:
            sessions[sid]["status"] = status
    try:
        result = Orchestrator(config=config).run(
            target         = target,
            session_id     = session_id,
            scan_mode      = scan_mode,
            requested_tests= requested_tests,
            status_callback= _cb,
        )
        sessions[session_id].update(result)
    except Exception as e:
        logger.error(f"[MAIN] Scan {session_id} failed: {e}", exc_info=True)
        sessions[session_id]["status"] = "error"
        sessions[session_id]["error"]  = str(e)


# ── Scan routes ───────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"agent":"AI VAPT Agent Platform","version":"3.0.0",
            "status":"online","docs":"/docs",
            "sessions":len(sessions),
            "checklist_items": len(_ka.get_all_test_names())}


@app.get("/health")
def health():
    return {"status":"healthy","sessions_active":len(sessions)}


@app.post("/scan", status_code=202)
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    session_id = str(uuid.uuid4())[:8].upper()
    config     = req.to_scan_config()

    sessions[session_id] = {
        "session_id":        session_id,
        "target":            req.target,
        "description":       req.description or "",
        "scan_mode":         req.scan_mode,
        "requested_tests":   req.requested_tests,
        "status":            "queued",
        "created_at":        datetime.utcnow().isoformat(),
        "auth_used":         config.build_auth_summary(),
        "enriched_findings": [],
        "summary":           {},
        "execution_plan":    {},
        "error":             None,
    }
    background_tasks.add_task(
        _run_scan, session_id, req.target, config,
        req.scan_mode, req.requested_tests
    )
    logger.info(f"[MAIN] Scan queued: {session_id} | {req.target} | "
                f"mode={req.scan_mode} | tests={req.requested_tests}")
    return {
        "session_id":    session_id,
        "target":        req.target,
        "scan_mode":     req.scan_mode,
        "requested_tests": req.requested_tests,
        "auth":          config.build_auth_summary(),
        "message":       "Scan started. Poll /session/{id}/status.",
    }


@app.get("/sessions")
def list_sessions():
    return {"count": len(sessions), "sessions": [
        {"session_id": sid, "target": s.get("target"),
         "scan_mode": s.get("scan_mode"),
         "status": s.get("status"),
         "auth_used": s.get("auth_used",""),
         "created_at": s.get("created_at"),
         "total_findings": len(s.get("enriched_findings",[])),
         "risk_rating": s.get("summary",{}).get("risk_rating","-")}
        for sid, s in sessions.items()
    ]}


@app.get("/session/{session_id}")
def get_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, f"Session '{session_id}' not found")
    return sessions[session_id]


@app.get("/session/{session_id}/status")
def get_status(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    s = sessions[session_id]
    return {"session_id":session_id,"status":s.get("status"),
            "total_findings":len(s.get("enriched_findings",[])),
            "summary":s.get("summary",{}),"error":s.get("error")}


@app.get("/session/{session_id}/plan")
def get_execution_plan(session_id: str):
    """See what the Knowledge Agent resolved for this session."""
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    return sessions[session_id].get("execution_plan", {})


@app.get("/session/{session_id}/findings")
def get_findings(session_id: str,
                 severity: Optional[str] = Query(None),
                 validated: Optional[bool] = Query(None),
                 module: Optional[str] = Query(None),
                 checklist_id: Optional[str] = Query(None)):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    findings = sessions[session_id].get("enriched_findings",[])
    if severity:     findings = [f for f in findings if f.get("severity","").lower() == severity.lower()]
    if module:       findings = [f for f in findings if f.get("module","").lower() == module.lower()]
    if checklist_id: findings = [f for f in findings if f.get("checklist_id") == checklist_id]
    if validated is not None:
        findings = [f for f in findings if f.get("validation_status") == ("approve" if validated else "pending")]
    return {"count":len(findings),"findings":findings}


@app.delete("/session/{session_id}")
def delete_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    del sessions[session_id]
    return {"message":f"Session {session_id} deleted"}


# ── Checklist routes ──────────────────────────────────────────────────────────

@app.get("/checklist")
def list_checklist(domain: Optional[str] = Query(None)):
    """
    List all available tests from the registry.
    Optionally filter by domain: web | network | cloud
    """
    if domain:
        names = _ka.get_tests_by_domain(domain)
    else:
        names = _ka.get_all_test_names()
    return {"count": len(names), "tests": names}


@app.get("/checklist/search")
def search_checklist(q: str = Query(..., min_length=2)):
    """Search tests by name or alias. Used for UI autocomplete."""
    results = _ka.search(q)
    return {"query": q, "count": len(results), "results": results}


@app.get("/checklist/{item_id}")
def get_checklist_item(item_id: str):
    """Get full definition of a single checklist item by ID (e.g. WEB-001)."""
    item = _ka.get_item_by_id(item_id.upper())
    if not item:
        raise HTTPException(404, f"Checklist item '{item_id}' not found")
    return item


@app.post("/checklist/preview")
def preview_execution_plan(
    target: str = Query(...),
    scan_mode: str = Query("full"),
    requested_tests: list[str] = Query(default=[])
):
    """
    Preview what the Knowledge Agent would resolve without running a scan.
    Useful for UI to show users what will be tested before they launch.
    """
    plan = _ka.resolve(target=target, mode=scan_mode,
                       requested_tests=requested_tests if requested_tests else None)
    return {
        "scan_mode":    plan.scan_mode,
        "tests_resolved": len(plan.resolved_tests),
        "fallback_used": plan.fallback_used,
        "resolution_log": plan.resolution_log,
        "agent_groups": {
            agent: [{"id": t.checklist_id, "name": t.canonical_name,
                     "source": t.source, "fallback": t.fallback}
                    for t in tests]
            for agent, tests in plan.agent_groups.items()
        }
    }


# ── Validation routes ─────────────────────────────────────────────────────────

@app.post("/validate/{session_id}")
def validate(session_id: str, req: ValidationRequest):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    findings = sessions[session_id].get("enriched_findings",[])
    finding  = next((f for f in findings if f.get("id") == req.finding_id), None)
    if not finding:
        raise HTTPException(404, f"Finding '{req.finding_id}' not found")
    try:
        validate_finding(finding, req.action, req.validator_name, req.notes)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"message":"Validation applied","finding_id":req.finding_id,"action":req.action}


@app.post("/validate/{session_id}/batch")
def batch_validate(session_id: str, req: BatchValidationRequest):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    findings = sessions[session_id].get("enriched_findings",[])
    updated  = validate_batch(findings, req.approved_ids,
                               req.rejected_ids, req.validator_name)
    return {"message":"Batch validation complete","stats":get_validation_stats(updated)}


# ── Report routes ─────────────────────────────────────────────────────────────

@app.get("/report/{session_id}")
def get_report(session_id: str,
               format: str = Query("json", pattern="^(json|html|pdf|csv|all|both)$")):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    s = sessions[session_id]
    if s.get("status") not in ("awaiting_validation","completed","error"):
        raise HTTPException(400, f"Scan not complete. Status: {s.get('status')}")
    paths = generate_report(s, format=format)
    return {"message":"Report generated","format":format,"files":paths}


@app.get("/report/{session_id}/download")
def download_report(session_id: str,
                    format: str = Query("html", pattern="^(json|html|pdf|csv)$")):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    s = sessions[session_id]
    if s.get("status") not in ("awaiting_validation","completed","error"):
        raise HTTPException(400, "Scan not complete yet")
    paths = generate_report(s, format=format)
    if not paths:
        raise HTTPException(500, "Report generation failed")
    path       = paths[0]
    ext        = path.split(".")[-1]
    mime_types = {"json":"application/json","html":"text/html",
                  "pdf":"application/pdf","csv":"text/csv"}
    return FileResponse(path, media_type=mime_types.get(ext,"application/octet-stream"),
                        filename=f"vapt_report_{session_id}.{ext}")
