"""
NetworkAgent — LLM-driven network security agent.

Replaces modules/network_module.py analysis logic and its 6-entry hardcoded
CVE dict. The LLM runs Nmap, looks up CVEs for detected service versions,
checks for auth weaknesses, and decides what constitutes a real finding.

Returns a dict compatible with the orchestrator and enrichment pipeline.
"""
import logging
import re
from datetime import datetime

from agents.base_agent import BaseAgent
from agents.tool_registry import build_registry
from agents.tools.nmap_tool import run_nmap
from agents.tools.cve_tool import search_cve
from agents.tools.http_tool import http_request
from agents.tools.finding_tool import report_finding

logger = logging.getLogger(__name__)

# ── System prompt ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a network security assessment agent. Your job is to discover exposed services, identify vulnerable software versions, and find authentication weaknesses on a target host.

INVESTIGATION ORDER — work through each phase in sequence:

PHASE 1 — PORT AND SERVICE SCAN
  run_nmap(target, ports="1-65535", flags=["-T4"])
  - If the target has known open ports from recon context, scan those first with version detection
  - Review every open port: service name, product, version, CPE
  - Note any service running an outdated or unusual version

PHASE 2 — CVE LOOKUP FOR DETECTED VERSIONS
  For each service where a product AND version was detected by Nmap:
  - search_cve(product, version)
  - Evaluate each CVE returned: is it exploitable in this context?
    Consider: CVSS score, attack vector (network vs local), complexity, whether PoC exists
  - Report HIGH/CRITICAL CVEs that are network-exploitable as findings
  - Skip CVEs that require local access or authentication you don't have

PHASE 3 — HIGH-RISK SERVICE CHECKS
  For these services if found open, perform targeted checks:

  HTTP/HTTPS (80, 443, 8080, 8443):
  - http_request("GET", "http://target:port/") — check for default pages, admin panels
  - Try: /manager (Tomcat), /phpmyadmin, /admin, /.env, /config.php

  FTP (21):
  - Note: anonymous FTP is a critical misconfiguration (test via Nmap script result or http probe)

  SSH (22):
  - Check Nmap detected version for known CVEs (e.g. OpenSSH < 7.2 username enumeration)

  TELNET (23):
  - Telnet open = immediate Medium finding (unencrypted protocol)

  SMTP (25):
  - Check for open relay indicators in Nmap service info

  DATABASE SERVICES (1433 MSSQL, 1521 Oracle, 3306 MySQL, 5432 PostgreSQL, 27017 MongoDB, 6379 Redis):
  - Exposed database ports are HIGH findings — databases should never be publicly accessible
  - Redis and MongoDB without auth = Critical

  RDP (3389):
  - Exposed RDP = Medium finding (brute force / BlueKeep surface)

  ELASTICSEARCH (9200):
  - http_request("GET", "http://target:9200/") — unauthenticated access = Critical
  - http_request("GET", "http://target:9200/_cat/indices") — index listing

  KUBERNETES (6443, 8001):
  - http_request("GET", "https://target:6443/api/v1/namespaces") — unauthenticated = Critical

FINDING TYPES — always include `type` in report_finding():
  vulnerable_version      — CVE found for detected service version
  open_port               — risky service exposed to internet (Telnet, RDP, exposed DB)
  auth_misconfiguration   — unauthenticated access to sensitive service (Redis, ES, MongoDB)
  information_disclosure  — default page, admin panel, config file exposure
  web_vulnerability       — web admin panel vulnerability (only if confirmed)

SEVERITY GUIDELINES:
  Critical: Unauthenticated access to database/cache (Redis, MongoDB, ES), CVE CVSS >= 9.0,
            exposed Kubernetes API unauthenticated, RCE-class CVE
  High:     CVE CVSS 7.0-8.9 on network-reachable service, exposed database port,
            exposed admin panel with default creds
  Medium:   Telnet open, RDP exposed, CVE CVSS 4.0-6.9, exposed SMTP, FTP open
  Low:      CVE CVSS < 4.0, informational Nmap findings
  Info:     Open port with no known vulnerability, up-to-date service version

EVIDENCE REQUIREMENTS — every report_finding() must include in evidence:
  host        — target IP or hostname
  port        — port number
  service     — service name and version detected
  curl_poc    — Nmap command or curl command that demonstrates the finding
  cve_id      — CVE identifier (for vulnerable_version findings)
  observation — what you confirmed (Nmap output excerpt or HTTP response snippet)

CALL report_finding() only for confirmed issues. A CVE in the database is not a finding
unless you have confirmed the vulnerable version is running. When all phases are complete
and you have no more checks to run, call done.
"""

# ── Agent class ────────────────────────────────────────────────────────────────

class NetworkAgent:
    """
    LLM-driven network security agent.
    Drop-in replacement for modules/network_module.run_network_scan().
    """

    def __init__(self, llm, scope: str = None):
        self.llm   = llm
        self.scope = scope

    def run(self, target: str, recon: dict = None,
            config=None, checklist_items=None, tool_filter=None) -> dict:

        registry = build_registry(run_nmap, search_cve, http_request, report_finding)

        # Build context from recon data so LLM knows what was already found
        recon_summary = _summarise_recon(recon or {})

        extra_context = ""
        if checklist_items:
            names = [getattr(t, "canonical_name", str(t)) for t in checklist_items]
            extra_context = f"\nFocus on these test categories: {', '.join(names)}"

        agent = BaseAgent(
            llm            = self.llm,
            tool_registry  = registry,
            system_prompt  = _SYSTEM_PROMPT,
            max_iterations = 50,
            scope          = self.scope or target,
        )

        goal = (
            f"Perform network security assessment on: {target}\n"
            f"Recon context: {recon_summary}"
            f"{extra_context}\n"
            f"Auth: {config.build_auth_summary() if config else 'Unauthenticated'}"
        )

        start  = datetime.utcnow()
        result = agent.run(goal=goal, context={"target": target, "recon": recon_summary})
        elapsed = (datetime.utcnow() - start).total_seconds()

        logger.info(
            f"[NETWORK_AGENT] Done — {result.iterations} iterations, "
            f"{result.tool_call_count} tool calls, "
            f"{len(result.findings)} findings, "
            f"status={result.status}"
        )

        return {
            "module":           "network",
            "target":           target,
            "findings":         _normalise_findings(result.findings, target),
            "tool_used":        "ai_network_agent",
            "auth_used":        config.build_auth_summary() if config else "Unauthenticated",
            "scan_time":        elapsed,
            "agent_status":     result.status,
            "agent_iterations": result.iterations,
            "agent_summary":    result.summary,
        }


# ── Recon context summariser ───────────────────────────────────────────────────

def _summarise_recon(recon: dict) -> str:
    """Build a concise recon summary to pass as context to the LLM."""
    ip        = recon.get("ip_address", "unknown")
    host_type = recon.get("host_type", "unknown")
    ports     = recon.get("open_ports", [])

    if ports:
        port_str = ", ".join(
            f"{p['port']}/{p.get('service', '?')}" for p in ports
        )
    else:
        port_str = "none detected in pre-scan"

    return (
        f"IP={ip}, host_type={host_type}, "
        f"pre-scan open ports: {port_str}"
    )


# ── Finding normalisation ──────────────────────────────────────────────────────

def _normalise_findings(findings: list, target: str) -> list:
    normalised = []
    for f in findings:
        finding = dict(f)

        if "remediation" in finding:
            finding["solution"] = finding.pop("remediation")
        if "severity" in finding:
            finding["risk"] = finding.pop("severity")
        if "cwe_id" in finding:
            finding["cwe"] = finding.pop("cwe_id")

        # Extract CVE from evidence or references
        refs = finding.pop("references", []) or []
        evidence = finding.get("evidence") or {}

        # LLM often puts cve_id directly in evidence
        if not finding.get("cve") and evidence.get("cve_id"):
            finding["cve"] = evidence["cve_id"]

        if not finding.get("cve"):
            for ref in refs:
                m = re.search(r"CVE-\d{4}-\d+", ref, re.IGNORECASE)
                if m:
                    finding["cve"] = m.group().upper()
                    break

        # Port and service from evidence
        if not finding.get("port") and evidence.get("port"):
            try:
                finding["port"] = int(evidence["port"])
            except (ValueError, TypeError):
                pass
        if not finding.get("service") and evidence.get("service"):
            finding["service"] = evidence["service"]

        if not finding.get("url"):
            port = finding.get("port", "")
            finding["url"] = f"{target}:{port}" if port else target

        if not finding.get("type"):
            finding["type"] = _infer_type(finding.get("name", ""))

        normalised.append(finding)
    return normalised


def _infer_type(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("cve-", "vulnerable", "outdated", "unpatched")):
        return "vulnerable_version"
    if any(k in n for k in ("unauthenticated", "default cred", "no auth",
                             "anonymous", "open access")):
        return "auth_misconfiguration"
    if any(k in n for k in ("telnet", "ftp", "rdp", "exposed", "open port")):
        return "open_port"
    if any(k in n for k in ("disclosure", "default page", "admin panel")):
        return "information_disclosure"
    return "open_port"
