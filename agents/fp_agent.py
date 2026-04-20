"""
False Positive Detection Agent — Phase 3

Uses Gemma 4 (via Ollama) to re-evaluate each finding and:
  1. Assign an AI-based confidence score (0.0–1.0)
  2. Flag likely false positives with a reason
  3. Write a professional analyst-quality description + impact + remediation

Falls back to heuristic scoring (Phase 2 behaviour) if Ollama is unavailable,
so the platform continues to work without LLM.
"""
import logging
from typing import Optional

from agents.llm_client import get_llm

logger = logging.getLogger(__name__)

# System prompt shared across all FP analysis calls
# SIMPLIFIED for Gemma 4: avoid complex reasoning that triggers extended thinking
_SYSTEM_PROMPT = """You are a security analyst. Classify findings and return JSON only."""


def analyse_findings(findings: list) -> list:
    """
    Run FP analysis on a list of enriched findings.

    For each finding:
    - If LLM available: get AI confidence score, description, impact, remediation
    - If LLM unavailable: return findings unchanged (heuristic scores remain)

    Returns the findings list with LLM fields added where available.
    """
    llm = get_llm()

    if not llm.is_available():
        logger.info("[FP-AGENT] LLM unavailable — using heuristic scores only")
        return findings

    logger.info(f"[FP-AGENT] Analysing {len(findings)} findings with {llm.model}")
    results = []

    for f in findings:
        try:
            enriched = _analyse_single(llm, f)
            results.append(enriched)
        except Exception as e:
            logger.warning(f"[FP-AGENT] Failed to analyse finding '{f.get('name')}': {e}")
            results.append(f)  # keep original on error

    confirmed    = sum(1 for r in results if r.get("fp_status") == "confirmed")
    false_pos    = sum(1 for r in results if r.get("fp_status") == "likely_false_positive")
    uncertain    = sum(1 for r in results if r.get("fp_status") == "uncertain")
    logger.info(
        f"[FP-AGENT] Done — confirmed={confirmed} | "
        f"likely_fp={false_pos} | uncertain={uncertain}"
    )
    return results


def _analyse_single(llm, finding: dict) -> dict:
    """
    Ask the LLM to evaluate one finding.
    Returns the finding dict with added LLM fields.
    """
    # Build a compact finding summary for the prompt
    summary = _build_finding_summary(finding)

    # Use a template-based approach to minimize Gemma thinking
    # Model fills in placeholders rather than generating from scratch
    user_prompt = f"""Fill in this JSON template about the finding:

{summary}

Fill in values (do NOT add thinking, do NOT explain, ONLY output JSON):
{{
  "confidence_score": <number from 0.0 to 1.0>,
  "fp_status": "confirmed|likely_false_positive|uncertain",
  "fp_reason": "brief reason",
  "ai_description": "technical description",
  "ai_impact": "business impact",
  "ai_remediation": "how to fix it"
}}"""

    result = llm.chat_json(
        system=_SYSTEM_PROMPT,
        user=user_prompt,
        temperature=0.1,
    )

    if not result:
        logger.debug(f"[FP-AGENT] No JSON response for: {finding.get('name')}")
        return finding

    # Merge LLM results into finding, preserving original fields
    updated = dict(finding)
    updated["ai_confidence_score"] = _clamp(result.get("confidence_score", finding.get("confidence_score", 0.5)))
    updated["fp_status"]           = result.get("fp_status", "uncertain")
    updated["fp_reason"]           = result.get("fp_reason", "")

    # Only overwrite description/solution if they're generic/empty
    if result.get("ai_description"):
        updated["ai_description"] = result["ai_description"]
        # Use AI description as the primary description if current one is short/generic
        if len(updated.get("description", "")) < 80:
            updated["description"] = result["ai_description"]

    if result.get("ai_impact"):
        updated["impact"] = result["ai_impact"]

    if result.get("ai_remediation"):
        updated["ai_remediation"] = result["ai_remediation"]
        # Use AI remediation if current solution is generic
        if len(updated.get("solution", "")) < 60:
            updated["solution"] = result["ai_remediation"]

    # Use AI confidence score as the primary confidence (override heuristic)
    updated["confidence_score"] = updated["ai_confidence_score"]
    updated["llm_analysed"]     = True

    logger.debug(
        f"[FP-AGENT] '{finding.get('name')}' → "
        f"conf={updated['confidence_score']:.2f} | status={updated['fp_status']}"
    )
    return updated


def _build_finding_summary(f: dict) -> str:
    """Build a compact text summary of a finding for the LLM prompt."""
    lines = [
        f"Name: {f.get('name', 'Unknown')}",
        f"Severity: {f.get('severity', 'Unknown')}",
        f"Module: {f.get('module', 'unknown')} | Tool: {f.get('tool_used', 'unknown')}",
        f"Target URL: {f.get('url', 'N/A')}",
        f"CVSS Score: {f.get('cvss_score', 'N/A')}",
        f"Current Description: {f.get('description', 'N/A')[:200]}",
    ]

    evidence = f.get("evidence", {})
    if evidence:
        if evidence.get("banner"):
            lines.append(f"Banner/Service Info: {evidence['banner'][:100]}")
        if evidence.get("response_headers"):
            lines.append(f"Response Headers: {str(evidence['response_headers'])[:200]}")
        if evidence.get("curl_poc"):
            lines.append(f"PoC Command: {evidence['curl_poc'][:150]}")

    return "\n".join(lines)


def _clamp(value, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a value to [lo, hi]."""
    try:
        return max(lo, min(hi, float(value)))
    except (TypeError, ValueError):
        return 0.5
