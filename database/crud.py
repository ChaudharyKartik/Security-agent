"""
database/crud.py

Data-access layer — all DB reads/writes go through here.
Business logic (orchestrator, main.py) never writes raw SQL.
"""
import logging
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from database.models import ScanSession, ScanFinding, AnalystFeedback, ScanReport

logger = logging.getLogger(__name__)


# ── Session ────────────────────────────────────────────────────────────────────

def create_session(db: Session, session_dict: dict) -> ScanSession:
    """Persist a new scan session record at scan start."""
    start = _parse_dt(session_dict.get("start_time")) or datetime.utcnow()

    obj = ScanSession(
        id              = session_dict["session_id"],
        target          = session_dict["target"],
        scan_mode       = session_dict.get("scan_mode", "full"),
        requested_tests = session_dict.get("requested_tests", []),
        status          = session_dict.get("status", "running"),
        auth_used       = session_dict.get("auth_used"),
        start_time      = start,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    logger.info(f"[DB] Session created: {obj.id}")
    return obj


def get_session(db: Session, session_id: str) -> Optional[ScanSession]:
    return db.query(ScanSession).filter(ScanSession.id == session_id).first()


def list_sessions(db: Session, limit: int = 100, offset: int = 0) -> list[ScanSession]:
    return (db.query(ScanSession)
              .order_by(ScanSession.start_time.desc())
              .offset(offset)
              .limit(limit)
              .all())


def update_session_status(db: Session, session_id: str, status: str) -> None:
    obj = db.query(ScanSession).filter(ScanSession.id == session_id).first()
    if obj:
        obj.status = status
        db.commit()


def finalise_session(db: Session, session_dict: dict) -> None:
    """Update session with final results after scan completes."""
    obj = db.query(ScanSession).filter(
        ScanSession.id == session_dict["session_id"]
    ).first()
    if not obj:
        logger.warning(f"[DB] finalise_session: {session_dict['session_id']} not found")
        return

    end = _parse_dt(session_dict.get("end_time")) or datetime.utcnow()

    obj.status           = session_dict.get("status", "completed")
    obj.end_time         = end
    obj.duration_seconds = session_dict.get("duration_seconds")
    obj.summary          = session_dict.get("summary", {})
    obj.execution_plan   = session_dict.get("execution_plan", {})
    obj.error            = session_dict.get("error")
    db.commit()
    logger.info(f"[DB] Session finalised: {obj.id} | status={obj.status}")


# ── Findings ───────────────────────────────────────────────────────────────────

def save_findings(db: Session, session_id: str, findings: list[dict]) -> int:
    """Bulk-upsert enriched findings for a session. Returns count saved."""
    valid = [f for f in findings if f.get("id")]
    if not valid:
        return 0

    # Bulk fetch all existing IDs in one query (avoids N+1)
    ids = [f["id"] for f in valid]
    existing_map = {
        obj.id: obj
        for obj in db.query(ScanFinding).filter(ScanFinding.id.in_(ids)).all()
    }

    for f in valid:
        fid = f["id"]
        validated_at = _parse_dt(f.get("validated_at"))
        enriched_at  = _parse_dt(f.get("enriched_at"))

        if fid in existing_map:
            _update_finding(existing_map[fid], f, session_id, validated_at, enriched_at)
        else:
            db.add(_build_finding(f, session_id, validated_at, enriched_at))

    db.commit()
    logger.info(f"[DB] {len(valid)} findings saved for session {session_id}")
    return len(valid)


def _parse_dt(value):
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return None


def _build_finding(f: dict, session_id: str,
                   validated_at, enriched_at) -> ScanFinding:
    return ScanFinding(
        id                     = f["id"],
        session_id             = session_id,
        name                   = f.get("name", ""),
        type                   = f.get("type"),
        module                 = f.get("module"),
        tool_used              = f.get("tool_used"),
        checklist_id           = f.get("checklist_id"),
        severity               = f.get("severity", "Info"),
        cvss_score             = f.get("cvss_score"),
        cvss_vector            = f.get("cvss_vector"),
        cvss_metrics           = f.get("cvss_metrics"),
        exploitability_score   = f.get("exploitability_score"),
        impact_score           = f.get("impact_score"),
        confidence_score       = f.get("confidence_score"),
        # AI analysis fields (Phase 3)
        llm_analysed           = f.get("llm_analysed", False),
        ai_confidence_score    = f.get("ai_confidence_score"),
        fp_status              = f.get("fp_status"),
        fp_reason              = f.get("fp_reason"),
        ai_description         = f.get("ai_description"),
        ai_remediation         = f.get("ai_remediation"),
        impact                 = f.get("impact"),
        target                 = f.get("target"),
        url                    = f.get("url"),
        port                   = f.get("port"),
        service                = f.get("service"),
        cve                    = f.get("cve"),
        cwe                    = f.get("cwe"),
        compliance             = f.get("compliance", []),
        description            = f.get("description"),
        solution               = f.get("solution"),
        exploitation_narrative = f.get("exploitation_narrative"),
        analyst_note           = f.get("analyst_note"),
        exploitability         = f.get("exploitability"),
        exploit_available      = f.get("exploit_available", False),
        attack_complexity      = f.get("attack_complexity"),
        privileges_required    = f.get("privileges_required"),
        evidence               = f.get("evidence", {}),
        validation_status      = f.get("validation_status", "pending"),
        validated_by           = f.get("validated_by"),
        validated_at           = validated_at,
        false_positive         = f.get("false_positive", False),
        enriched_at            = enriched_at,
    )


def _update_finding(obj: ScanFinding, f: dict, session_id: str,
                    validated_at, enriched_at) -> None:
    obj.session_id             = session_id
    obj.severity               = f.get("severity", obj.severity)
    obj.cvss_score             = f.get("cvss_score", obj.cvss_score)
    obj.cvss_vector            = f.get("cvss_vector", obj.cvss_vector)
    obj.cvss_metrics           = f.get("cvss_metrics", obj.cvss_metrics)
    obj.confidence_score       = f.get("confidence_score", obj.confidence_score)
    # AI fields
    obj.llm_analysed           = f.get("llm_analysed", obj.llm_analysed)
    obj.ai_confidence_score    = f.get("ai_confidence_score", obj.ai_confidence_score)
    obj.fp_status              = f.get("fp_status", obj.fp_status)
    obj.fp_reason              = f.get("fp_reason", obj.fp_reason)
    obj.ai_description         = f.get("ai_description", obj.ai_description)
    obj.ai_remediation         = f.get("ai_remediation", obj.ai_remediation)
    obj.impact                 = f.get("impact", obj.impact)
    obj.description            = f.get("description", obj.description)
    obj.solution               = f.get("solution", obj.solution)
    obj.evidence               = f.get("evidence", obj.evidence)
    obj.validation_status      = f.get("validation_status", obj.validation_status)
    obj.validated_by           = f.get("validated_by", obj.validated_by)
    obj.validated_at           = validated_at or obj.validated_at
    obj.false_positive         = f.get("false_positive", obj.false_positive)


def get_findings(db: Session, session_id: str,
                 include_rejected: bool = True) -> list[ScanFinding]:
    q = db.query(ScanFinding).filter(ScanFinding.session_id == session_id)
    if not include_rejected:
        q = q.filter(ScanFinding.false_positive == False)  # noqa: E712
    return q.all()


def update_finding_validation(db: Session, finding_id: str,
                              action: str, validator_name: str,
                              notes: Optional[str] = None) -> Optional[ScanFinding]:
    obj = db.query(ScanFinding).filter(ScanFinding.id == finding_id).first()
    if not obj:
        return None
    obj.validation_status = action
    obj.validated_by      = validator_name
    obj.validated_at      = datetime.utcnow()
    obj.false_positive    = (action == "reject")
    db.commit()
    db.refresh(obj)
    return obj


# ── Feedback ───────────────────────────────────────────────────────────────────

def save_feedback(db: Session, session_id: str, finding_id: str,
                  action: str, validator_name: str,
                  notes: Optional[str] = None) -> AnalystFeedback:
    """Append an immutable feedback event (audit trail)."""
    obj = AnalystFeedback(
        session_id     = session_id,
        finding_id     = finding_id,
        action         = action,
        validator_name = validator_name,
        notes          = notes,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    logger.info(f"[DB] Feedback saved: finding={finding_id} action={action} by={validator_name}")
    return obj


def get_feedback(db: Session, session_id: str) -> list[AnalystFeedback]:
    return (db.query(AnalystFeedback)
              .filter(AnalystFeedback.session_id == session_id)
              .order_by(AnalystFeedback.created_at.desc())
              .all())


# ── Reports ────────────────────────────────────────────────────────────────────

def save_report(db: Session, session_id: str,
                format: str, file_path: str) -> ScanReport:
    obj = ScanReport(session_id=session_id, format=format, file_path=file_path)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    logger.info(f"[DB] Report saved: {file_path}")
    return obj


def get_reports(db: Session, session_id: str) -> list[ScanReport]:
    return (db.query(ScanReport)
              .filter(ScanReport.session_id == session_id)
              .order_by(ScanReport.created_at.desc())
              .all())


# ── Aggregate helpers ─────────────────────────────────────────────────────────

def count_sessions(db: Session) -> int:
    return db.query(ScanSession).count()


def db_ping(db: Session) -> str:
    try:
        db.query(ScanSession).limit(1).all()
        return "ok"
    except Exception as e:
        return f"error: {e}"


def get_finding_by_id(db: Session, finding_id: str) -> Optional[ScanFinding]:
    return db.query(ScanFinding).filter(ScanFinding.id == finding_id).first()


# ── Utility ────────────────────────────────────────────────────────────────────

def session_to_dict(obj: ScanSession) -> dict:
    """Convert a ScanSession ORM object back to the dict shape the API expects."""
    return {
        "session_id":        obj.id,
        "target":            obj.target,
        "scan_mode":         obj.scan_mode,
        "requested_tests":   obj.requested_tests or [],
        "status":            obj.status,
        "auth_used":         obj.auth_used or "Unauthenticated",
        "error":             obj.error,
        "start_time":        obj.start_time.isoformat() if obj.start_time else None,
        "end_time":          obj.end_time.isoformat()   if obj.end_time   else None,
        "duration_seconds":  obj.duration_seconds,
        "summary":           obj.summary or {},
        "execution_plan":    obj.execution_plan or {},
        "enriched_findings": [],  # populated separately by get_findings()
        "agents_executed":   (obj.summary or {}).get("agents_run", []),
        "raw_results":       {},  # raw results not persisted (too large)
    }


def finding_to_dict(obj: ScanFinding) -> dict:
    """Convert a ScanFinding ORM object to the dict shape the API expects."""
    return {
        "id":                    obj.id,
        "name":                  obj.name,
        "type":                  obj.type,
        "module":                obj.module,
        "tool_used":             obj.tool_used,
        "checklist_id":          obj.checklist_id,
        "severity":              obj.severity,
        "cvss_score":            obj.cvss_score,
        "cvss_vector":           obj.cvss_vector,
        "cvss_metrics":          obj.cvss_metrics or {},
        "exploitability_score":  obj.exploitability_score,
        "impact_score":          obj.impact_score,
        "confidence_score":      obj.confidence_score,
        # AI analysis fields
        "llm_analysed":          obj.llm_analysed or False,
        "ai_confidence_score":   obj.ai_confidence_score,
        "fp_status":             obj.fp_status,
        "fp_reason":             obj.fp_reason,
        "ai_description":        obj.ai_description,
        "ai_remediation":        obj.ai_remediation,
        "impact":                obj.impact,
        "target":                obj.target,
        "url":                   obj.url,
        "port":                  obj.port,
        "service":               obj.service,
        "cve":                   obj.cve,
        "cwe":                   obj.cwe,
        "compliance":            obj.compliance or [],
        "description":           obj.description or "",
        "solution":              obj.solution or "",
        "exploitation_narrative":obj.exploitation_narrative or "",
        "analyst_note":          obj.analyst_note or "",
        "exploitability":        obj.exploitability or "",
        "exploit_available":     obj.exploit_available or False,
        "attack_complexity":     obj.attack_complexity,
        "privileges_required":   obj.privileges_required,
        "evidence":              obj.evidence or {},
        "validation_status":     obj.validation_status,
        "validated_by":          obj.validated_by,
        "validated_at":          obj.validated_at.isoformat() if obj.validated_at else None,
        "false_positive":        obj.false_positive,
        "enriched_at":           obj.enriched_at.isoformat() if obj.enriched_at else None,
    }
