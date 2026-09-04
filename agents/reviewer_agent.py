"""
ReviewerAgent — LLM-driven human review gate.

Replaces the 3-if-statement triage logic with LLM-generated review briefs.
For every Critical/High finding the LLM writes a structured brief so the
analyst can make an informed decision quickly.

Flow:
  build_review_queue(findings)
    → triage: Critical/High queued, likely_FP auto-suppressed
    → for each queued finding: generate_brief(finding) via LLM
    → returns queue dict with briefs attached

Analyst decisions (unchanged):
  confirm | false_positive | downgrade | escalate | needs_retest
"""
import logging
import json
from typing import Optional

from cvss import clamp_score_to_severity

logger = logging.getLogger(__name__)

REVIEW_SEVERITIES = {"Critical", "High"}
VALID_ACTIONS     = {"confirm", "false_positive", "downgrade", "escalate", "needs_retest"}
_SEV_ORDER        = ["Info", "Low", "Medium", "High", "Critical"]

_BRIEF_SYSTEM_PROMPT = """You are a senior penetration tester reviewing a scan finding before it goes to an analyst.
Write a concise review brief that helps the analyst make a fast, informed decision.

Output ONLY valid JSON with exactly these fields:
{
  "evidence_quality":   "strong | moderate | weak",
  "fp_likelihood":      "unlikely | possible | likely",
  "fp_reasoning":       "one sentence — why this could or could not be a false positive",
  "attack_chain":       "concrete step-by-step: how attacker discovers → exploits → impacts",
  "business_impact":    "specific business consequence if exploited",
  "suggested_decision": "confirm | false_positive | downgrade | needs_retest",
  "reasoning":          "one or two sentences justifying the suggested decision",
  "confidence":         "high | medium | low"
}

Be direct. Analysts are busy. No hedging, no fluff."""


class ReviewerAgent:

    def __init__(self, llm=None):
        self.llm = llm

    # ── Queue building ─────────────────────────────────────────────────────────

    def build_review_queue(self, findings: list) -> dict:
        """
        Triage findings, generate LLM briefs for Critical/High, return queue dict.
        If no LLM is available, briefs are skipped (backward compatible).
        """
        items           = []
        auto_suppressed = 0

        for f in findings:
            # `or "uncertain"` (not `.get(..., "uncertain")`) — a freshly
            # enriched finding never has this key at all, so the default
            # fires correctly. But a finding that's round-tripped through the
            # DB always has the key present with value None (finding_to_dict
            # sets it explicitly), which .get()'s default does NOT catch —
            # silently excluding every non-Critical/High finding with no
            # recorded fp_status from the queue after any DB rebuild.
            fp_status = f.get("fp_status") or "uncertain"
            severity  = f.get("severity", "Info")

            if fp_status == "likely_false_positive":
                auto_suppressed += 1
                continue

            reason = None
            if severity in REVIEW_SEVERITIES:
                reason = f"{severity} severity — analyst sign-off required"
            elif fp_status == "uncertain":
                reason = "AI confidence uncertain — analyst review required"

            if not reason:
                continue

            brief = self._generate_brief(f) if self.llm else {}

            items.append({
                "finding_id":       f.get("id", ""),
                "name":             f.get("name", "Unknown"),
                "severity":         severity,
                "cvss_score":       f.get("cvss_score") or 0.0,
                "url":              f.get("url", ""),
                "type":             f.get("type", ""),
                "module":           f.get("module", ""),
                "reason":           reason,
                "fp_status":        fp_status,
                "confidence_score": f.get("confidence_score") or 0.5,
                "review_status":    "pending",
                "brief":            brief,
            })

        items.sort(key=lambda x: (
            -(_SEV_ORDER.index(x["severity"]) if x["severity"] in _SEV_ORDER else 0),
            -(x["cvss_score"] or 0),
        ))

        logger.info(
            f"[REVIEWER] {len(items)} queued | "
            f"{auto_suppressed} auto-suppressed | "
            f"briefs={'yes' if self.llm else 'skipped (no LLM)'}"
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
        """
        Refresh both the aggregate counts AND each item's own review_status/
        severity/cvss_score from its matching finding. Previously only the
        aggregate counts were refreshed here — individual items stayed frozen
        at "pending" forever (even within one uninterrupted session), so the
        queue UI never actually showed a finding as decided.
        """
        findings_by_id = {f.get("id"): f for f in findings if f.get("id")}
        items = []
        for item in queue.get("items", []):
            f = findings_by_id.get(item.get("finding_id"))
            if f:
                item = {
                    **item,
                    "review_status": f.get("review_status", item.get("review_status", "pending")),
                    "severity":      f.get("severity", item.get("severity")),
                    "cvss_score":    f.get("cvss_score", item.get("cvss_score")),
                }
            items.append(item)

        reviewed = sum(1 for f in findings if f.get("reviewed"))
        pending  = max(0, queue.get("needs_review", 0) - reviewed)
        return {**queue, "items": items, "reviewed": reviewed, "pending": pending,
                "complete": pending == 0}

    # ── LLM brief generation ───────────────────────────────────────────────────

    def _generate_brief(self, finding: dict) -> dict:
        """Ask the LLM to write a review brief for a single finding."""
        user_prompt = (
            f"Finding: {finding.get('name', '')} [{finding.get('severity', '')}]\n"
            f"Type: {finding.get('type', '')}\n"
            f"URL: {finding.get('url', '')}\n"
            f"CVSS: {finding.get('cvss_score', 'N/A')}\n"
            f"Tool: {finding.get('tool_used', '')}\n"
            f"Module: {finding.get('module', '')}\n"
            f"Description: {finding.get('description', '')[:400]}\n"
            f"Evidence: {json.dumps(finding.get('evidence') or {})[:600]}\n"
            f"Analyst note: {finding.get('analyst_note', '')}"
        )

        try:
            brief = self.llm.chat_json(
                system      = _BRIEF_SYSTEM_PROMPT,
                user        = user_prompt,
                temperature = 0.1,
                max_tokens  = 512,
            )
            if brief and isinstance(brief, dict):
                logger.debug(
                    f"[REVIEWER] Brief for {finding.get('id','?')} "
                    f"({finding.get('name','')[:40]}): "
                    f"suggested={brief.get('suggested_decision')} "
                    f"fp={brief.get('fp_likelihood')}"
                )
                return brief
        except Exception as e:
            logger.warning(f"[REVIEWER] Brief generation failed for "
                           f"{finding.get('id','?')}: {e}")
        return {}

    # ── Decision application ───────────────────────────────────────────────────

    def apply_decisions(self, findings: list, decisions: list) -> list:
        """
        Apply analyst decisions to findings.

        Each decision dict:
          finding_id   — str
          action       — confirm | false_positive | downgrade | escalate | needs_retest
          analyst      — str
          notes        — str (optional)
          new_severity — str (required for downgrade / escalate)
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
                if "original_cvss_score" not in f:
                    f["original_cvss_score"] = f.get("cvss_score")
                f["severity"]          = "Info"
                f["cvss_score"]        = clamp_score_to_severity(f.get("cvss_score"), "Info")
                f["validation_status"] = "rejected"
                f["fp_status"]         = "confirmed_false_positive"
                f["false_positive"]    = True

            elif action in ("downgrade", "escalate"):
                new_sev = d.get("new_severity", "")
                if new_sev in _SEV_ORDER:
                    if "original_cvss_score" not in f:
                        f["original_cvss_score"] = f.get("cvss_score")
                    f["severity"]   = new_sev
                    f["cvss_score"] = clamp_score_to_severity(f.get("cvss_score"), new_sev)
                else:
                    logger.warning(f"[REVIEWER] {action} for {fid}: "
                                   f"invalid new_severity '{new_sev}'")
                f["validation_status"] = "confirmed"

            elif action == "confirm":
                f["validation_status"] = "confirmed"

            elif action == "needs_retest":
                f["validation_status"] = "needs_retest"

            logger.debug(f"[REVIEWER] {fid} ({f.get('name','')[:40]}) → {action}")
            updated.append(f)

        confirmed = sum(1 for f in updated if f.get("review_status") == "confirm")
        rejected  = sum(1 for f in updated if f.get("review_status") == "false_positive")
        logger.info(f"[REVIEWER] Applied — confirmed={confirmed} fp_rejected={rejected}")
        return updated
