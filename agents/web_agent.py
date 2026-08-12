"""
WebAgent — LLM-driven web application security agent.

Replaces modules/web_module.py detection logic and modules/probes.py entirely.
The LLM decides what to probe, crafts payloads, interprets tool output, and
confirms findings. Python executes tool calls and enforces scope.

Returns a dict compatible with the orchestrator and enrichment pipeline.
"""
import logging
import os
import re
from datetime import datetime
from urllib.parse import urlparse

from agents.base_agent import BaseAgent
from agents.tool_registry import build_registry
from agents.tools.http_tool import http_request
from agents.tools.nuclei_tool import run_nuclei
from agents.tools.zap_tool import run_zap
from agents.tools.finding_tool import report_finding

logger = logging.getLogger(__name__)

# ── System prompt (role + core rules only — sent on every LLM call) ───────────

_SYSTEM_PROMPT = (
    "You are a web application penetration tester. "
    "Only call report_finding() when you have confirmed evidence in a tool response — "
    "never on suspicion alone. Do not report missing security headers (recon handles those). "
    "One finding per unique vulnerability instance. Call done when all testing is complete."
)

# ── Methodology (sent once in the initial user message, not repeated per call) ─

_METHODOLOGY = """
TESTING PHASES:
1. FINGERPRINT: GET target → note stack/inputs/auth; GET target/nonexistent → check error disclosure
2. TEMPLATE SCAN: run_nuclei(target, tags=["cve","misconfig","exposed-panels","default-login","takeover"]) → confirm each result before reporting
3. PASSIVE SCAN: run_zap(target,"spider") → run_zap(target,"passive") → confirm ZAP alerts before reporting
4. MANUAL TESTING (based on observations from phases 1-3):
   XSS:              inject <script>alert(1)</script> into visible params — confirm unencoded reflection
   SQLi:             inject ' OR '1'='1 and 1' AND SLEEP(3)-- — confirm error/boolean diff/time delay
   Command inject:   ;id |whoami in server-side params
   Path traversal:   /../../../etc/passwd in file path params
   IDOR:             try adjacent numeric IDs if seen in URLs
   Forced browsing:  /admin /dashboard /config /backup /.git/config
   Default creds:    admin/admin admin/password (login forms only)
   CSRF:             check POST forms for CSRF token presence and validation
   SSRF:             http://169.254.169.254/latest/meta-data/ in URL params
   CORS:             Origin: https://evil.com → check Access-Control-Allow-Origin
   Open redirect:    ?next= ?url= ?redirect= → https://evil.com — confirm 3xx to external domain

FINDING TYPES: web_vulnerability | auth_misconfiguration | missing_security_header | information_disclosure | insecure_cookie
SEVERITY: Critical=SQLi+RCE+auth_bypass | High=StoredXSS+SSRF+IDOR+default_creds | Medium=ReflectedXSS+CSRF+open_redirect+CORS | Low=self_XSS+verbose_errors | Info=version_disclosure
EVIDENCE fields (all required): url, method, request, response, curl_poc, parameter"""

# ── Agent class ────────────────────────────────────────────────────────────────

class WebAgent:
    """
    LLM-driven web application security agent.
    Drop-in replacement for modules/web_module.run_web_scan().
    """

    def __init__(self, llm, scope: str = None):
        self.llm   = llm
        self.scope = scope

    def run(self, target: str, config=None, checklist_items=None, tool_filter=None,
            session_id: str = None) -> dict:
        scope    = self.scope or _host_from_url(target)
        registry = build_registry(http_request, run_nuclei, run_zap, report_finding)
        if tool_filter:
            keep     = set(tool_filter) | {"report_finding"}
            registry = {k: v for k, v in registry.items() if k in keep}

        extra_context = ""
        if checklist_items:
            names = [getattr(t, "canonical_name", str(t)) for t in checklist_items]
            extra_context = f"\nFocus on these test categories: {', '.join(names)}"

        agent = BaseAgent(
            llm            = self.llm,
            tool_registry  = registry,
            system_prompt  = _SYSTEM_PROMPT,
            max_iterations = int(os.getenv("WEB_MAX_ITERATIONS", "20")),
            scope          = scope,
            session_id     = session_id,
            agent_name     = "web",
        )

        goal = (
            f"Perform web application security testing on: {target}\n"
            f"Auth: {config.build_auth_summary() if config else 'Unauthenticated'}"
            f"{extra_context}"
            f"{_METHODOLOGY}"
        )

        start  = datetime.utcnow()
        result = agent.run(goal=goal, context={"target": target})
        elapsed = (datetime.utcnow() - start).total_seconds()

        logger.info(
            f"[WEB_AGENT] Done — {result.iterations} iterations, "
            f"{result.tool_call_count} tool calls, "
            f"{len(result.findings)} findings, "
            f"status={result.status}"
        )

        return {
            "module":           "web",
            "target":           target,
            "findings":         _normalise_findings(result.findings, target),
            "tool_used":        "ai_web_agent",
            "auth_used":        config.build_auth_summary() if config else "Unauthenticated",
            "scan_time":        elapsed,
            "agent_status":     result.status,
            "agent_iterations": result.iterations,
            "agent_summary":    result.summary,
        }


# ── Finding normalisation ──────────────────────────────────────────────────────

def _normalise_findings(findings: list, target: str) -> list:
    """
    Translate report_finding() field names to what enrichment.py expects.
    Same logic as ReconAgent — centralised here per-agent until Phase 5
    consolidation in the orchestrator.
    """
    normalised = []
    for f in findings:
        finding = dict(f)

        if "remediation" in finding:
            finding["solution"] = finding.pop("remediation")
        if "severity" in finding:
            finding["risk"] = finding.pop("severity")
        if "cwe_id" in finding:
            finding["cwe"] = finding.pop("cwe_id")

        # Extract CVE from references
        refs = finding.pop("references", []) or []
        for ref in refs:
            if "CVE-" in ref.upper():
                m = re.search(r"CVE-\d{4}-\d+", ref, re.IGNORECASE)
                if m:
                    finding["cve"] = m.group().upper()
                    break

        # Pull url from evidence if not set directly
        if not finding.get("url"):
            evidence = finding.get("evidence") or {}
            finding["url"] = evidence.get("url") or target

        # Pull param from evidence for dedup key in enrichment
        if not finding.get("param"):
            evidence = finding.get("evidence") or {}
            finding["param"] = evidence.get("parameter", "")

        if not finding.get("type"):
            finding["type"] = _infer_type(finding.get("name", ""))

        normalised.append(finding)
    return normalised


def _infer_type(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("xss", "cross-site scripting", "injection", "sqli",
                             "ssrf", "command", "redirect", "csrf", "cors")):
        return "web_vulnerability"
    if any(k in n for k in ("auth", "login", "password", "credential",
                             "session", "lockout", "brute")):
        return "auth_misconfiguration"
    if any(k in n for k in ("cookie", "httponly", "samesite")):
        return "insecure_cookie"
    if any(k in n for k in ("disclosure", "stack trace", "debug", "version",
                             "banner", "error", "directory listing")):
        return "information_disclosure"
    if any(k in n for k in ("header", "csp", "hsts", "frame")):
        return "missing_security_header"
    return "web_vulnerability"


def _host_from_url(target: str) -> str:
    parsed = urlparse(target)
    return parsed.netloc or parsed.path or target
