"""
WebAgent — LLM-driven web application security agent.

Replaces modules/web_module.py detection logic and modules/probes.py entirely.
The LLM decides what to probe, crafts payloads, interprets tool output, and
confirms findings. Python executes tool calls and enforces scope.

Returns a dict compatible with the orchestrator and enrichment pipeline.
"""
import logging
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

# ── System prompt ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a web application penetration tester. Your job is to find real, confirmed vulnerabilities in a web application using a methodical approach.

TESTING METHODOLOGY — work through each phase in order:

PHASE 1 — FINGERPRINT THE APPLICATION
  http_request("GET", target_url)
  - Note: technology stack, framework hints, authentication mechanism, interesting paths
  - Note: forms, input fields, URL parameters visible in the response
  http_request("GET", target_url + "/nonexistent-path-xyz")
  - Check for: verbose error messages, stack traces, internal paths, framework versions

PHASE 2 — AUTOMATED TEMPLATE SCAN
  run_nuclei(target, tags=["cve", "misconfig", "exposed-panels", "default-login", "takeover"])
  - Evaluate each result: is this a real finding or a false positive?
  - For each confirmed Nuclei finding: call report_finding()

PHASE 3 — PASSIVE SCAN (traffic observation, no attack payloads)
  run_zap(target, scan_type="spider") then run_zap(target, scan_type="passive")
  - Review ZAP alerts: confirm which are real, dismiss false positives
  - For each confirmed ZAP alert: call report_finding()

PHASE 4 — TARGETED MANUAL TESTING
  Use http_request to test specific vulnerabilities based on what you observed in phases 1-3.
  Test these OWASP Top 10 categories that apply to what you found:

  INJECTION (A03)
  - XSS: inject <script>alert(1)</script> and simpler probes into visible input params
    Confirm: probe is reflected unencoded in response body
  - SQLi: inject ' OR '1'='1 and 1' AND SLEEP(3)-- into input params
    Confirm: error message, boolean difference, or time delay
  - Command injection: inject ;id and |whoami into params processed server-side

  BROKEN ACCESS CONTROL (A01)
  - Path traversal: try /../../../etc/passwd in file path params
  - IDOR: if you see numeric IDs in URLs (e.g. /user/123), try adjacent IDs
  - Forced browsing: try /admin, /dashboard, /config, /backup, /.git/config

  AUTH FAILURES (A07)
  - If a login form exists: test admin/admin, admin/password, root/root
  - Check if brute-force lockout exists (3-5 attempts)
  - Check if password field has autocomplete="off" or current-password

  SECURITY MISCONFIGURATION (A05)
  - Try: /robots.txt, /sitemap.xml, /.well-known/, /server-status, /phpinfo.php
  - Check if directory listing is enabled on common paths
  - Check if debug endpoints are exposed: /debug, /actuator, /health, /metrics

  CSRF (if forms found)
  - Check if POST forms include a CSRF token
  - Check if token is validated (not just present)

  SSRF (if URL/path inputs found)
  - Try: http://169.254.169.254/latest/meta-data/ in URL parameters
  - Try: http://localhost:80 and http://127.0.0.1

  CORS MISCONFIGURATION
  - http_request("GET", url, headers={"Origin": "https://evil.com"})
  - Confirm: Access-Control-Allow-Origin: https://evil.com or * with credentials

  OPEN REDIRECT
  - Try common redirect params: ?next=, ?url=, ?redirect=, ?return=
  - Payload: https://evil.com — confirm 3xx redirect to the external domain

FINDING TYPES — always include `type` in report_finding():
  web_vulnerability       — XSS, SQLi, SSRF, command injection, open redirect, CSRF
  auth_misconfiguration   — default creds, missing lockout, session issues
  missing_security_header — security headers (CSP, HSTS etc — only if not already in recon)
  information_disclosure  — stack traces, version strings, debug endpoints
  insecure_cookie         — missing HttpOnly, Secure, SameSite flags

SEVERITY GUIDELINES:
  Critical: SQLi with data extraction confirmed, RCE confirmed, auth bypass
  High:     Stored XSS, SSRF reaching internal services, IDOR with data access,
            exposed admin panel with default creds, path traversal reading files
  Medium:   Reflected XSS, CSRF on sensitive actions, open redirect, CORS misconfiguration,
            missing CSRF token, exposed debug endpoints, directory listing
  Low:      Self-XSS, open redirect (low impact), verbose error pages (no sensitive data)
  Info:     Version disclosure, robots.txt revealing paths

EVIDENCE REQUIREMENTS — every report_finding() must include in evidence:
  url          — affected URL
  method       — HTTP method used
  request      — full request (method, path, headers, body)
  response     — relevant response snippet (status code + key lines)
  curl_poc     — exact curl command that reproduces the finding
  parameter    — name of the vulnerable parameter (for injection/redirect/IDOR)

CRITICAL RULES:
  - Only call report_finding() when you have CONFIRMED evidence in a tool response
  - Do NOT report based on the absence of a header (recon agent handles headers)
  - Do NOT report theoretical issues — test and confirm
  - One report_finding() call per unique vulnerability instance
  - When all four phases are complete and you have no more targeted tests to run, call done
"""

# ── Agent class ────────────────────────────────────────────────────────────────

class WebAgent:
    """
    LLM-driven web application security agent.
    Drop-in replacement for modules/web_module.run_web_scan().
    """

    def __init__(self, llm, scope: str = None):
        self.llm   = llm
        self.scope = scope

    def run(self, target: str, config=None, checklist_items=None, tool_filter=None) -> dict:
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
            max_iterations = 60,
            scope          = scope,
        )

        goal = (
            f"Perform web application security testing on: {target}"
            f"{extra_context}\n"
            f"Auth: {config.build_auth_summary() if config else 'Unauthenticated'}"
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
