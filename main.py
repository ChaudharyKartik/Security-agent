"""
FastAPI Entry Point — AI Security Testing Agent v1.0
"""
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from orchestrator import Orchestrator
from validator import validate_finding, validate_batch, get_validation_stats
from report_generator import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Security Testing Agent",
    version="1.0.0",
    description="Multi-agent automated security testing platform. For authorized use only.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (upgrade to Redis/PostgreSQL in Phase 2)
sessions: dict = {}


# ── Request / Response Models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    run_cloud: bool = False
    description: Optional[str] = None

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Target cannot be empty")
        return v.strip()


class ValidationRequest(BaseModel):
    finding_id: str
    action: str       # approve | reject | escalate
    validator_name: str
    notes: Optional[str] = None


class BatchValidationRequest(BaseModel):
    approved_ids: list[str] = []
    rejected_ids: list[str] = []
    validator_name: str


# ── Background scan task ───────────────────────────────────────────────────────

def _run_scan_background(session_id: str, target: str, run_cloud: bool):
    def _status_update(sid, status):
        if sid in sessions:
            sessions[sid]["status"] = status

    try:
        sessions[session_id]["status"] = "running"
        result = Orchestrator(config={"run_cloud": run_cloud}).run(
            target, session_id, status_callback=_status_update
        )
        sessions[session_id].update(result)
    except Exception as e:
        logger.error(f"[MAIN] Scan {session_id} failed: {e}", exc_info=True)
        sessions[session_id]["status"] = "error"
        sessions[session_id]["error"] = str(e)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "agent":   "AI Security Testing Agent",
        "version": "1.0.0",
        "status":  "online",
        "docs":    "/docs",
        "sessions": len(sessions),
    }


@app.get("/health")
def health():
    return {"status": "healthy", "sessions_active": len(sessions)}


@app.post("/scan", status_code=202)
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    session_id = str(uuid.uuid4())[:8].upper()
    sessions[session_id] = {
        "session_id":        session_id,
        "target":            req.target,
        "description":       req.description or "",
        "status":            "queued",
        "created_at":        datetime.utcnow().isoformat(),
        "enriched_findings": [],
        "summary":           {},
        "error":             None,
    }
    background_tasks.add_task(_run_scan_background, session_id, req.target, req.run_cloud)
    logger.info(f"[MAIN] Scan queued: {session_id} -> {req.target}")
    return {
        "session_id": session_id,
        "message":    "Scan started. Poll /session/{id}/status for updates.",
        "target":     req.target,
        "docs":       f"/session/{session_id}",
    }


@app.get("/sessions")
def list_sessions():
    return {
        "count": len(sessions),
        "sessions": [
            {
                "session_id":     sid,
                "target":         s.get("target"),
                "description":    s.get("description", ""),
                "status":         s.get("status"),
                "created_at":     s.get("created_at"),
                "total_findings": len(s.get("enriched_findings", [])),
                "risk_rating":    s.get("summary", {}).get("risk_rating", "-"),
            }
            for sid, s in sessions.items()
        ],
    }


@app.get("/session/{session_id}")
def get_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return sessions[session_id]


@app.get("/session/{session_id}/status")
def get_status(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    s = sessions[session_id]
    return {
        "session_id":     session_id,
        "status":         s.get("status"),
        "total_findings": len(s.get("enriched_findings", [])),
        "summary":        s.get("summary", {}),
        "error":          s.get("error"),
    }


@app.get("/session/{session_id}/findings")
def get_findings(session_id: str,
                 severity: Optional[str] = Query(None),
                 validated: Optional[bool] = Query(None)):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    findings = sessions[session_id].get("enriched_findings", [])

    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]
    if validated is not None:
        if validated:
            findings = [f for f in findings if f.get("validation_status") == "approve"]
        else:
            findings = [f for f in findings if f.get("validation_status") == "pending"]

    return {"count": len(findings), "findings": findings}


@app.delete("/session/{session_id}")
def delete_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    del sessions[session_id]
    return {"message": f"Session {session_id} deleted"}


@app.post("/validate/{session_id}")
def validate(session_id: str, req: ValidationRequest):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    findings = sessions[session_id].get("enriched_findings", [])
    finding = next((f for f in findings if f.get("id") == req.finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{req.finding_id}' not found")

    try:
        validate_finding(finding, req.action, req.validator_name, req.notes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "message":    "Validation applied",
        "finding_id": req.finding_id,
        "action":     req.action,
    }


@app.post("/validate/{session_id}/batch")
def batch_validate(session_id: str, req: BatchValidationRequest):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    findings = sessions[session_id].get("enriched_findings", [])
    updated  = validate_batch(findings, req.approved_ids, req.rejected_ids, req.validator_name)
    return {
        "message": "Batch validation complete",
        "stats":   get_validation_stats(updated),
    }


@app.get("/report/{session_id}")
def get_report(session_id: str, format: str = Query("json", pattern="^(json|html|both)$")):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    s = sessions[session_id]
    if s.get("status") not in ("awaiting_validation", "completed", "error"):
        raise HTTPException(status_code=400,
                            detail=f"Scan not complete yet. Current status: {s.get('status')}")

    paths = generate_report(s, format=format)
    return {
        "message": "Report generated",
        "format":  format,
        "files":   paths,
    }
