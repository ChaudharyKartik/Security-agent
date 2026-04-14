"""Validator Module — approve / reject (FP) / escalate findings."""
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)
VALID_ACTIONS = {"approve","reject","escalate"}


def validate_finding(finding: dict, action: str, validator_name: str,
                     notes: Optional[str] = None) -> dict:
    if action not in VALID_ACTIONS:
        raise ValueError(f"Invalid action '{action}'. Must be one of: {VALID_ACTIONS}")
    finding["validation_status"] = action
    finding["validated_by"]      = validator_name
    finding["validated_at"]      = datetime.utcnow().isoformat()
    finding["validator_notes"]   = notes or ""
    finding["false_positive"]    = (action == "reject")
    logger.info(f"[VALIDATOR] [{finding.get('id','?')}] {action} by {validator_name}")
    return finding


def validate_batch(findings: list, approved_ids: list, rejected_ids: list,
                   validator_name: str) -> list:
    for f in findings:
        fid = f.get("id","")
        if fid in approved_ids:   validate_finding(f, "approve",  validator_name)
        elif fid in rejected_ids: validate_finding(f, "reject",   validator_name)
    return findings


def get_validated_findings(findings: list, include_pending: bool = False) -> list:
    if include_pending:
        return [f for f in findings if f.get("validation_status") != "reject"]
    return [f for f in findings if f.get("validation_status") == "approve"]


def get_validation_stats(findings: list) -> dict:
    stats = {"total":len(findings),"pending":0,"approve":0,"reject":0,"escalate":0}
    for f in findings:
        s = f.get("validation_status","pending")
        stats[s] = stats.get(s,0) + 1
    return stats
