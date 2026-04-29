"""
Reviewer Agent — Phase 3

Triages enriched findings after FP analysis and builds a human review queue.

Rules:
  - Critical / High severity  → always queued for analyst sign-off
  - fp_status == "uncertain"  → queued (AI wasn't confident enough)
  - fp_status == "likely_false_positive" → auto-suppressed, never queued
  - Everything else           → passes through without review

Analyst decisions: confirm | false_positive | downgrade | escalate | needs_retest
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

REVIEW_SEVERITIES = {"Critical", "High"}
VALID_ACTIONS     = {"confirm", "false_positive", "downgrade", "escalate", "needs_retest"}
_SEV_ORDER        = ["Info", "Low", "Medium", "High", "Critical"]


class ReviewerAgent:

    # ── Queue building ─────────────────────────────────────────────────────────

    def triage(self, findings: list) -> list:
        """Return list of findings that need human review, highest-risk first."""
        items = []
        for f in findings:
            fp_status = f.get("fp_status", "uncertain")
            severity  = f.get("severity", "Info")

            if fp_status == "likely_false_positive":
                continue   # auto-suppressed — no human needed

            reason = None
            if severity in REVIEW_SEVERITIES:
                reason = f"{severity} severity — analyst sign-off required"
            elif fp_status == "uncertain":
                reason = "AI confidence uncertain — analyst review required"

            if reason:
                items.append({
                    "finding_id":       f.get("id", ""),
                    "name":             f.get("name", "Unknown"),
                    "severity":         severity,
                    "cvss_score":       f.get("cvss_score") or 0.0,
                    "url":              f.get("url", ""),
                    "reason":           reason,
                    "fp_status":        fp_status,
                    "confidence_score": f.get("confidence_score") or 0.5,
                    "review_status":    "pending",
                })

        items.sort(key=lambda x: (
            -(_SEV_ORDER.index(x["severity"]) if x["severity"] in _SEV_ORDER else 0),
            -(x["cvss_score"] or 0),
        ))
        return items

    def build_review_queue(self, findings: list) -> dict:
        """Build the review queue dict stored on the session object."""
        items           = self.triage(findings)
        auto_suppressed = sum(1 for f in findings
                              if f.get("fp_status") == "likely_false_positive")

        logger.info(
            f"[REVIEWER] {len(items)} need review | "
            f"{auto_suppressed} auto-suppressed | "
            f"{len(findings) - len(items) - auto_suppressed} passed through"
        )

        return {
            "total_findings":  len(findings),
            "needs_review":    len(items),
            "auto_suppressed": auto_suppressed,
            "reviewed":        0,
            "pending":         len(items),
            "complete":        len(items) == 0,
            "items":           items,
        }

    def refresh_progress(self, queue: dict, findings: list) -> dict:
        """Recompute reviewed/pending counters after decisions are applied."""
        reviewed = sum(1 for f in findings if f.get("reviewed"))
        pending  = max(0, queue.get("needs_review", 0) - reviewed)
        return {**queue, "reviewed": reviewed, "pending": pending,
                "complete": pending == 0}

    # ── Decision application ───────────────────────────────────────────────────

    def apply_decisions(self, findings: list, decisions: list) -> list:
        """
        Apply analyst decisions to findings.

        Each decision dict must have:
          finding_id  — str
          action      — confirm | false_positive | downgrade | escalate | needs_retest
          analyst     — str (name)
          notes       — str (optional)
          new_severity — str (required for downgrade / escalate)

        Returns a new list; originals are not mutated.
        """
        dec_map = {d["finding_id"]: d for d in decisions}
        updated = []

        for f in findings:
            fid = f.get("id", "")
            d   = dec_map.get(fid)

            if not d:
                updated.append(f)
                continue

            action = d.get("action", "")
            if action not in VALID_ACTIONS:
                logger.warning(f"[REVIEWER] Unknown action '{action}' for {fid} — skipped")
                updated.append(f)
                continue

            f = dict(f)
            f["review_status"]  = action
            f["reviewer"]       = d.get("analyst", "Security Analyst")
            f["reviewer_notes"] = d.get("notes", "")
            f["reviewed"]       = True

            if action == "false_positive":
                f["severity"]          = "Info"
                f["validation_status"] = "rejected"
                f["fp_status"]         = "confirmed_false_positive"

            elif action in ("downgrade", "escalate"):
                new_sev = d.get("new_severity", "")
                if new_sev in _SEV_ORDER:
                    f["severity"] = new_sev
                else:
                    logger.warning(f"[REVIEWER] {action} for {fid}: invalid new_severity '{new_sev}'")
                f["validation_status"] = "confirmed"

            elif action == "confirm":
                f["validation_status"] = "confirmed"

            elif action == "needs_retest":
                f["validation_status"] = "needs_retest"

            logger.debug(f"[REVIEWER] {fid} ({f.get('name','')[:40]}) → {action}")
            updated.append(f)

        confirmed = sum(1 for f in updated if f.get("review_status") == "confirm")
        rejected  = sum(1 for f in updated if f.get("review_status") == "false_positive")
        logger.info(f"[REVIEWER] Applied — confirmed={confirmed} | fp_rejected={rejected}")
        return updated
