"""
FastAPI Entry Point — v4 (Phase 2: DB persistence)

Changes from v3:
  - DB initialised on startup (SQLite by default, PostgreSQL via DATABASE_URL)
  - In-memory `sessions` dict kept for active scans (real-time status polling)
  - Completed sessions read from DB on restart (no data loss)
  - All validation actions persisted to DB as audit trail
  - Report paths saved to DB on generation
  - /sessions endpoint reads from DB (paginated)
  - /session/{id} falls back to DB if not in memory

Scan modes supported:
  full | checklist | single | owasp
"""
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from orchestrator import Orchestrator
from agents.knowledge_agent import KnowledgeAgent, MODE_FULL
from scan_config import ScanConfig
from validator import validate_finding, validate_batch, get_validation_stats
from report_generator import generate_report
from database.connection import init_db, get_db
from database import crud

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# httpx logs every HTTP request at INFO — suppress to WARNING to avoid noise
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("[MAIN] Database ready.")
    yield


app = FastAPI(
    title="AI VAPT Agent Platform",
    version="4.0.0",
    description="Knowledge Agent-driven VAPT. Checklist-first, OWASP fallback. Authorized use only.",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# In-memory store — used ONLY for active scans (real-time status polling)
# Completed sessions are read from DB. On restart active scans are lost (acceptable).
sessions: dict = {}

_ka = KnowledgeAgent()   # singleton — loaded once at startup


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:          str
    description:     Optional[str]  = None

    scan_mode:       str            = "full"    # full | checklist | single | owasp
    requested_tests: list[str]      = []

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
    """
    Runs in a FastAPI BackgroundTask.
    Opens its own DB session (cannot share the request session across threads).
    """
    from database.connection import SessionLocal
    db = SessionLocal()

    def _cb(sid, status):
        if sid in sessions:
            sessions[sid]["status"] = status

    try:
        result = Orchestrator(config=config).run(
            target          = target,
            session_id      = session_id,
            scan_mode       = scan_mode,
            requested_tests = requested_tests,
            status_callback = _cb,
            db              = db,
        )
        sessions[session_id].update(result)
    except Exception as e:
        logger.error(f"[MAIN] Scan {session_id} failed: {e}", exc_info=True)
        sessions[session_id]["status"] = "error"
        sessions[session_id]["error"]  = str(e)
        try:
            crud.update_session_status(db, session_id, "error")
        except Exception:
            pass
    finally:
        db.close()


# ── Utility ────────────────────────────────────────────────────────────────────

def _get_session_dict(session_id: str, db: Session) -> dict:
    """
    Return the session as a dict.
    Priority: in-memory (active/recent) → DB (completed, survived restart).
    """
    if session_id in sessions:
        return sessions[session_id]

    db_obj = crud.get_session(db, session_id)
    if not db_obj:
        raise HTTPException(404, f"Session '{session_id}' not found")

    # Rebuild dict + attach DB findings
    s = crud.session_to_dict(db_obj)
    db_findings = crud.get_findings(db, session_id)
    s["enriched_findings"] = [crud.finding_to_dict(f) for f in db_findings]
    return s


# ── Core routes ───────────────────────────────────────────────────────────────

@app.get("/")
def root(db: Session = Depends(get_db)):
    return {
        "agent":           "AI VAPT Agent Platform",
        "version":         "4.0.0",
        "status":          "online",
        "docs":            "/docs",
        "sessions_active": len(sessions),
        "sessions_total":  crud.count_sessions(db),
        "checklist_items": len(_ka.get_all_test_names()),
    }


@app.get("/health")
def health(db: Session = Depends(get_db)):
    return {
        "status":          "healthy",
        "db":              crud.db_ping(db),
        "sessions_active": len(sessions),
    }


# ── Scan routes ───────────────────────────────────────────────────────────────

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
        "start_time":        datetime.utcnow().isoformat(),
        "end_time":          None,
        "duration_seconds":  None,
        "auth_used":         config.build_auth_summary(),
        "enriched_findings": [],
        "summary":           {},
        "execution_plan":    {},
        "raw_results":       {},
        "agents_executed":   [],
        "error":             None,
    }

    background_tasks.add_task(
        _run_scan, session_id, req.target, config,
        req.scan_mode, req.requested_tests
    )
    logger.info(f"[MAIN] Scan queued: {session_id} | {req.target} | "
                f"mode={req.scan_mode} | tests={req.requested_tests}")
    return {
        "session_id":      session_id,
        "target":          req.target,
        "scan_mode":       req.scan_mode,
        "requested_tests": req.requested_tests,
        "auth":            config.build_auth_summary(),
        "message":         "Scan started. Poll /session/{id}/status.",
    }


@app.get("/sessions")
def list_sessions(
    limit:  int = Query(50, ge=1, le=500),
    offset: int = Query(0,  ge=0),
    db: Session = Depends(get_db),
):
    """List all sessions — reads from DB (survives restarts)."""
    db_sessions = crud.list_sessions(db, limit=limit, offset=offset)
    total = db.query(crud.ScanSession).count()
    rows = []
    for obj in db_sessions:
        # Overlay in-memory status if scan is still active
        mem = sessions.get(obj.id, {})
        rows.append({
            "session_id":     obj.id,
            "target":         obj.target,
            "scan_mode":      obj.scan_mode,
            "status":         mem.get("status", obj.status),
            "auth_used":      obj.auth_used or "",
            "start_time":     obj.start_time.isoformat() if obj.start_time else None,
            "end_time":       obj.end_time.isoformat()   if obj.end_time   else None,
            "duration_seconds": obj.duration_seconds,
            "total_findings": len(mem.get("enriched_findings", [])) or
                              (obj.summary or {}).get("total_findings", 0),
            "risk_rating":    (obj.summary or {}).get("risk_rating", "-"),
        })
    return {"total": total, "count": len(rows), "offset": offset, "sessions": rows}


@app.get("/session/{session_id}")
def get_session(session_id: str, db: Session = Depends(get_db)):
    return _get_session_dict(session_id, db)


@app.get("/session/{session_id}/status")
def get_status(session_id: str, db: Session = Depends(get_db)):
    s = _get_session_dict(session_id, db)
    return {
        "session_id":     session_id,
        "status":         s.get("status"),
        "total_findings": len(s.get("enriched_findings", [])),
        "summary":        s.get("summary", {}),
        "error":          s.get("error"),
    }


@app.get("/session/{session_id}/plan")
def get_execution_plan(session_id: str, db: Session = Depends(get_db)):
    """Show what the Knowledge Agent resolved for this session."""
    return _get_session_dict(session_id, db).get("execution_plan", {})


@app.get("/session/{session_id}/findings")
def get_findings(
    session_id:   str,
    severity:     Optional[str]  = Query(None),
    validated:    Optional[bool] = Query(None),
    module:       Optional[str]  = Query(None),
    checklist_id: Optional[str]  = Query(None),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
    db: Session = Depends(get_db),
):
    s        = _get_session_dict(session_id, db)
    findings = s.get("enriched_findings", [])

    if severity:
        findings = [f for f in findings
                    if f.get("severity", "").lower() == severity.lower()]
    if module:
        findings = [f for f in findings
                    if f.get("module", "").lower() == module.lower()]
    if checklist_id:
        findings = [f for f in findings
                    if f.get("checklist_id") == checklist_id]
    if validated is not None:
        want = "approve" if validated else "pending"
        findings = [f for f in findings if f.get("validation_status") == want]
    if min_confidence is not None:
        findings = [f for f in findings
                    if (f.get("confidence_score") or 0) >= min_confidence]

    return {"count": len(findings), "findings": findings}


@app.delete("/session/{session_id}")
def delete_session(session_id: str, db: Session = Depends(get_db)):
    if session_id in sessions:
        del sessions[session_id]
    db_obj = crud.get_session(db, session_id)
    if db_obj:
        db.delete(db_obj)
        db.commit()
        return {"message": f"Session {session_id} deleted from memory and DB"}
    return {"message": f"Session {session_id} removed from memory (not in DB)"}


# ── Checklist routes ───────────────────────────────────────────────────────────

@app.get("/checklist")
def list_checklist(domain: Optional[str] = Query(None)):
    """List all available tests. Filter by domain: web | network | cloud"""
    names = _ka.get_tests_by_domain(domain) if domain else _ka.get_all_test_names()
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
    target:          str       = Query(...),
    scan_mode:       str       = Query("full"),
    requested_tests: list[str] = Query(default=[]),
):
    """Preview the Knowledge Agent's resolution without running a scan."""
    plan = _ka.resolve(target=target, mode=scan_mode,
                       requested_tests=requested_tests if requested_tests else None)
    return {
        "scan_mode":       plan.scan_mode,
        "tests_resolved":  len(plan.resolved_tests),
        "fallback_used":   plan.fallback_used,
        "resolution_log":  plan.resolution_log,
        "agent_groups": {
            agent: [{"id": t.checklist_id, "name": t.canonical_name,
                     "source": t.source, "fallback": t.fallback}
                    for t in tests]
            for agent, tests in plan.agent_groups.items()
        },
    }


# ── Validation routes ─────────────────────────────────────────────────────────

@app.post("/validate/{session_id}")
def validate(session_id: str, req: ValidationRequest,
             db: Session = Depends(get_db)):
    s = _get_session_dict(session_id, db)

    # Find in memory first (fast path), then build from DB
    findings = s.get("enriched_findings", [])
    finding  = next((f for f in findings if f.get("id") == req.finding_id), None)

    if not finding:
        db_f = crud.get_finding_by_id(db, req.finding_id)
        if not db_f:
            raise HTTPException(404, f"Finding '{req.finding_id}' not found")
        finding = crud.finding_to_dict(db_f)
        finding["session_id"] = session_id

    try:
        validate_finding(finding, req.action, req.validator_name,
                         notes=req.notes, db=db)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if session_id in sessions:
        for f in sessions[session_id].get("enriched_findings", []):
            if f.get("id") == req.finding_id:
                f.update(finding)
                break

    return {"message": "Validation applied", "finding_id": req.finding_id,
            "action": req.action, "persisted": True}


@app.post("/validate/{session_id}/batch")
def batch_validate(session_id: str, req: BatchValidationRequest,
                   db: Session = Depends(get_db)):
    s        = _get_session_dict(session_id, db)
    findings = s.get("enriched_findings", [])
    updated  = validate_batch(findings, req.approved_ids,
                               req.rejected_ids, req.validator_name, db=db)

    # Sync back to in-memory if active
    if session_id in sessions:
        sessions[session_id]["enriched_findings"] = updated

    return {
        "message": "Batch validation complete",
        "stats":   get_validation_stats(updated),
    }


@app.get("/session/{session_id}/feedback")
def get_feedback(session_id: str, db: Session = Depends(get_db)):
    """Return the full analyst feedback audit trail for a session."""
    _get_session_dict(session_id, db)   # verify session exists
    rows = crud.get_feedback(db, session_id)
    return {
        "session_id": session_id,
        "count":      len(rows),
        "feedback": [
            {
                "id":             r.id,
                "finding_id":     r.finding_id,
                "action":         r.action,
                "validator_name": r.validator_name,
                "notes":          r.notes,
                "created_at":     r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


# ── Report routes ─────────────────────────────────────────────────────────────

@app.get("/report/{session_id}")
def get_report(
    session_id: str,
    format: str = Query("json", pattern="^(json|html|pdf|csv|professional|all|both)$"),
    db: Session = Depends(get_db),
):
    s = _get_session_dict(session_id, db)
    if s.get("status") not in ("awaiting_validation", "completed", "error"):
        raise HTTPException(400, f"Scan not complete. Status: {s.get('status')}")

    paths = generate_report(s, format=format)

    # Persist generated report paths to DB
    for path in paths:
        ext = path.rsplit(".", 1)[-1]
        try:
            crud.save_report(db, session_id, ext, path)
        except Exception:
            pass

    return {"message": "Report generated", "format": format, "files": paths}


@app.get("/report/{session_id}/download")
def download_report(
    session_id: str,
    format: str = Query("html", pattern="^(json|html|pdf|csv|professional)$"),
    db: Session = Depends(get_db),
):
    s = _get_session_dict(session_id, db)
    if s.get("status") not in ("awaiting_validation", "completed", "error"):
        raise HTTPException(400, "Scan not complete yet")

    try:
        paths = generate_report(s, format=format)
    except Exception as e:
        logger.error(f"[REPORT] Generation failed for {session_id}: {e}", exc_info=True)
        raise HTTPException(500, f"Report generation failed: {e}")
    if not paths:
        raise HTTPException(500, "Report generation produced no output")

    path  = paths[0]
    ext   = path.rsplit(".", 1)[-1]
    mime  = {"json": "application/json", "html": "text/html",
             "pdf":  "application/pdf",  "csv":  "text/csv"}

    try:
        crud.save_report(db, session_id, ext, path)
    except Exception:
        pass

    return FileResponse(
        path,
        media_type=mime.get(ext, "application/octet-stream"),
        filename=f"vapt_report_{session_id}.{ext}",
    )


@app.get("/session/{session_id}/reports")
def list_reports(session_id: str, db: Session = Depends(get_db)):
    """List all generated report files for a session."""
    _get_session_dict(session_id, db)
    rows = crud.get_reports(db, session_id)
    return {
        "session_id": session_id,
        "count":      len(rows),
        "reports": [
            {
                "id":        r.id,
                "format":    r.format,
                "file_path": r.file_path,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }
