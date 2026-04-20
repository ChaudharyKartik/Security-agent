"""
database/models.py

SQLAlchemy ORM table definitions.
All JSON columns use Text + JSON serialisation so they work in both
SQLite (no native JSON type) and PostgreSQL (native JSONB switchable later).
"""
import json
from datetime import datetime
from sqlalchemy import (
    Column, String, Float, Integer, Boolean, Text, DateTime, ForeignKey
)
from sqlalchemy.orm import relationship
from database.connection import Base


# ── Custom JSON column helper ──────────────────────────────────────────────────

class JSONText(Text):
    """Stores Python dict/list as JSON string — compatible with SQLite + PG."""

    class Comparator(Text.Comparator):
        pass

    def bind_processor(self, dialect):
        def process(value):
            if value is None:
                return None
            return json.dumps(value, default=str)
        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            if value is None:
                return None
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                return value
        return process


# ── Tables ─────────────────────────────────────────────────────────────────────

class ScanSession(Base):
    """Top-level record for each scan run."""
    __tablename__ = "scan_sessions"

    id               = Column(String(64),  primary_key=True)
    target           = Column(String(512), nullable=False)
    scan_mode        = Column(String(32),  nullable=False, default="full")
    requested_tests  = Column(JSONText,    nullable=True)    # list[str]
    status           = Column(String(32),  nullable=False, default="running")
    auth_used        = Column(String(128), nullable=True)
    error            = Column(Text,        nullable=True)
    start_time       = Column(DateTime,    nullable=False, default=datetime.utcnow)
    end_time         = Column(DateTime,    nullable=True)
    duration_seconds = Column(Float,       nullable=True)
    summary          = Column(JSONText,    nullable=True)    # dict
    execution_plan   = Column(JSONText,    nullable=True)    # dict

    # Relationships
    findings  = relationship("ScanFinding",    back_populates="session",
                             cascade="all, delete-orphan")
    feedback  = relationship("AnalystFeedback", back_populates="session",
                             cascade="all, delete-orphan")
    reports   = relationship("ScanReport",     back_populates="session",
                             cascade="all, delete-orphan")


class ScanFinding(Base):
    """One enriched finding from a scan session."""
    __tablename__ = "scan_findings"

    id                    = Column(String(32),  primary_key=True)   # FIND-XXXXXXXX
    session_id            = Column(String(64),  ForeignKey("scan_sessions.id"), nullable=False)

    # Core taxonomy
    name                  = Column(String(512), nullable=False)
    type                  = Column(String(128), nullable=True)
    module                = Column(String(64),  nullable=True)
    tool_used             = Column(String(64),  nullable=True)
    checklist_id          = Column(String(32),  nullable=True)

    # Severity + scoring
    severity              = Column(String(16),  nullable=False, default="Info")
    cvss_score            = Column(Float,       nullable=True)
    cvss_vector           = Column(String(128), nullable=True)
    cvss_metrics          = Column(JSONText,    nullable=True)
    exploitability_score  = Column(Float,       nullable=True)
    impact_score          = Column(Float,       nullable=True)
    confidence_score      = Column(Float,       nullable=True)   # 0.0–1.0 (heuristic or AI)

    # AI Analysis (Phase 3 — Gemma 4 via Ollama)
    llm_analysed          = Column(Boolean,    nullable=False, default=False)
    ai_confidence_score   = Column(Float,       nullable=True)   # 0.0–1.0 from LLM
    fp_status             = Column(String(32),  nullable=True)   # confirmed|likely_false_positive|uncertain
    fp_reason             = Column(Text,        nullable=True)   # LLM explanation
    ai_description        = Column(Text,        nullable=True)   # LLM-written description
    ai_remediation        = Column(Text,        nullable=True)   # LLM-written remediation
    impact                = Column(Text,        nullable=True)   # LLM-written impact statement

    # Location
    target                = Column(String(512), nullable=True)
    url                   = Column(String(512), nullable=True)
    port                  = Column(Integer,     nullable=True)
    service               = Column(String(64),  nullable=True)

    # References
    cve                   = Column(String(32),  nullable=True)
    cwe                   = Column(String(32),  nullable=True)
    compliance            = Column(JSONText,    nullable=True)  # list[str]

    # Finding body
    description           = Column(Text,       nullable=True)
    solution              = Column(Text,       nullable=True)
    exploitation_narrative= Column(Text,       nullable=True)
    analyst_note          = Column(Text,       nullable=True)
    exploitability        = Column(String(128),nullable=True)
    exploit_available     = Column(Boolean,    nullable=True, default=False)
    attack_complexity     = Column(String(8),  nullable=True)
    privileges_required   = Column(String(8),  nullable=True)

    # Evidence (PoC, request, response, etc.)
    evidence              = Column(JSONText,   nullable=True)   # dict

    # Validation
    validation_status     = Column(String(32), nullable=False, default="pending")
    validated_by          = Column(String(128),nullable=True)
    validated_at          = Column(DateTime,   nullable=True)
    false_positive        = Column(Boolean,    nullable=False, default=False)

    # Timestamps
    enriched_at           = Column(DateTime,   nullable=True)
    created_at            = Column(DateTime,   nullable=False, default=datetime.utcnow)


    # Relationships
    session   = relationship("ScanSession",    back_populates="findings")
    feedbacks = relationship("AnalystFeedback", back_populates="finding",
                             cascade="all, delete-orphan")


class AnalystFeedback(Base):
    """Audit trail of every approve/reject/escalate action by an analyst."""
    __tablename__ = "analyst_feedback"

    id             = Column(Integer,    primary_key=True, autoincrement=True)
    session_id     = Column(String(64), ForeignKey("scan_sessions.id"), nullable=False)
    finding_id     = Column(String(32), ForeignKey("scan_findings.id"), nullable=False)
    action         = Column(String(32), nullable=False)  # approve | reject | escalate
    validator_name = Column(String(128),nullable=False)
    notes          = Column(Text,       nullable=True)
    created_at     = Column(DateTime,   nullable=False, default=datetime.utcnow)

    # Relationships
    session = relationship("ScanSession", back_populates="feedback")
    finding = relationship("ScanFinding", back_populates="feedbacks")


class ScanReport(Base):
    """Tracks generated report files linked to a session."""
    __tablename__ = "scan_reports"

    id         = Column(Integer,    primary_key=True, autoincrement=True)
    session_id = Column(String(64), ForeignKey("scan_sessions.id"), nullable=False)
    format     = Column(String(16), nullable=False)   # json | html | pdf | csv
    file_path  = Column(String(512),nullable=False)
    created_at = Column(DateTime,   nullable=False, default=datetime.utcnow)

    session = relationship("ScanSession", back_populates="reports")
