"""
NetworkAgent — LLM-driven network security agent.

Replaces modules/network_module.py analysis logic and its 6-entry hardcoded
CVE dict. The LLM runs Nmap, looks up CVEs for detected service versions,
checks for auth weaknesses, and decides what constitutes a real finding.

Returns a dict compatible with the orchestrator and enrichment pipeline.
"""
import logging
import os
import re
from datetime import datetime

from agents.base_agent import BaseAgent
from agents.tool_registry import build_registry
from agents.tools.nmap_tool import run_nmap
from agents.tools.cve_tool import search_cve
from agents.tools.http_tool import http_request
from agents.tools.finding_tool import report_finding

logger = logging.getLogger(__name__)

# ── System prompt (role + core rules only — sent on every LLM call) ───────────

_SYSTEM_PROMPT = (
    "You are a network security assessment agent. "
    "Only call report_finding() for confirmed issues — a CVE entry is not a finding "
    "unless you confirmed the vulnerable version is actually running. "
    "Call done when all phases are complete."
)

# ── Methodology (sent once in the initial user message, not repeated per call) ─

_METHODOLOGY = """
PHASES:
1. PORT SCAN: run_nmap(target, ports="1-65535", flags=["-T4"]) — review service/version/CPE per open port
2. CVE LOOKUP: search_cve(product, version) for each detected service — report only network-exploitable High/Critical CVEs
3. HIGH-RISK SERVICE CHECKS:
   HTTP/HTTPS(80/443/8080/8443): GET / → check default pages; try /manager /phpmyadmin /admin /.env
   FTP(21):   anonymous access = Critical
   SSH(22):   check Nmap version for CVEs
   Telnet(23): open = Medium (unencrypted protocol)
   DBs(1433/1521/3306/5432/27017/6379): exposed = High; Redis/MongoDB no auth = Critical
   RDP(3389): exposed = Medium
   Elasticsearch(9200): GET / and /_cat/indices — unauth = Critical
   Kubernetes(6443/8001): GET /api/v1/namespaces — unauth = Critical

FINDING TYPES: vulnerable_version | open_port | auth_misconfiguration | information_disclosure
SEVERITY: Critical=unauth_DB+CVSS≥9+unauth_K8s | High=CVSS7-8.9+exposed_DB+default_creds | Medium=Telnet+RDP+CVSS4-6.9 | Low=CVSS<4 | Info=open_port_no_vuln
EVIDENCE fields (all required): host, port, service, curl_poc, cve_id, observation"""

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
            config=None, checklist_items=None, tool_filter=None,
            session_id: str = None) -> dict:

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
            max_iterations = int(os.getenv("NETWORK_MAX_ITERATIONS", "15")),
            scope          = self.scope or target,
            auth_headers   = config.build_auth_headers() if config else None,
            session_id     = session_id,
            agent_name     = "network",
        )

        goal = (
            f"Perform network security assessment on: {target}\n"
            f"Recon context: {recon_summary}\n"
            f"Auth: {config.build_auth_summary() if config else 'Unauthenticated'}"
            f"{extra_context}"
            f"{_METHODOLOGY}"
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
        port_str = ", ".join(str(p) for p in ports)
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
