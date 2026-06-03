"""
ReconAgent — sequential data-gathering agent with single LLM analysis pass.

Replaces the ReAct loop with direct tool execution:
  1. Python runs all recon tools in a fixed sequence
  2. Single LLM call analyses all collected results and generates findings

Tools used:
  dns_lookup   — A/NS/MX/TXT/CNAME records, email security (SPF/DMARC/DKIM)
  run_nmap     — port/service discovery, host type determination
  ssl_check    — TLS cert + weak protocol detection (only if port 443 open)
  run_nuclei   — tech fingerprinting + misconfig checks (web targets only)
"""
import json
import logging
import re
from datetime import datetime
from urllib.parse import urlparse

from agents.tools.dns_tool import dns_lookup
from agents.tools.ssl_tool import ssl_check
from agents.tools.nmap_tool import run_nmap
from agents.tools.nuclei_tool import run_nuclei

logger = logging.getLogger(__name__)

_WEB_PORTS           = {80, 443, 8080, 8443, 8000, 8888}
_MAX_NUCLEI_FINDINGS = 30   # cap before sending to LLM to stay within token budget

_ANALYSIS_SYSTEM = (
    "You are a security analyst reviewing reconnaissance data. "
    "Identify security findings from the results provided.\n\n"
    "For each finding output a JSON object with:\n"
    "  name        — short descriptive name\n"
    "  severity    — one of: Critical, High, Medium, Low, Info\n"
    "  type        — one of: ssl_error, missing_security_header, "
    "information_disclosure, web_vulnerability, network_exposure\n"
    "  evidence    — dict with: url, curl_poc, observation\n"
    "  remediation — concise fix recommendation\n\n"
    "Output ONLY a JSON array of finding objects. "
    "Empty array [] if nothing found. No markdown, no explanation."
)


class ReconAgent:
    """
    Sequential recon agent. Runs tools directly, analyses results in one LLM call.
    Drop-in replacement for the previous ReAct-based ReconAgent.
    """

    def __init__(self, llm, scope: str = None):
        self.llm   = llm
        self.scope = scope

    def run(self, target: str, config=None) -> dict:
        hostname, scheme = _parse_target(target)
        start = datetime.utcnow()

        # ── Step 1: DNS records ────────────────────────────────────────────────
        dns = {
            "A":     dns_lookup(hostname, "A"),
            "NS":    dns_lookup(hostname, "NS"),
            "MX":    dns_lookup(hostname, "MX"),
            "TXT":   dns_lookup(hostname, "TXT"),
            "CNAME": dns_lookup(hostname, "CNAME"),
        }
        logger.info(f"[RECON] DNS done — IP: {dns['A'].get('records', [None])[0]}")

        # ── Step 2: Port scan ──────────────────────────────────────────────────
        nmap       = run_nmap(hostname, ports="1-1000", flags=["-T4"])
        open_ports = _extract_open_ports(nmap)
        logger.info(f"[RECON] Nmap done — open ports: {sorted(open_ports)}")

        # ── Step 3: TLS inspection (only if 443 reachable) ────────────────────
        has_tls = 443 in open_ports or scheme == "https"
        has_web = bool(open_ports & _WEB_PORTS) or scheme in ("http", "https")

        tls = ssl_check(hostname) if has_tls else None
        if tls:
            logger.info(f"[RECON] SSL done — weak: {tls.get('weak_protocols', [])}")

        # ── Step 4: Nuclei tech/ssl/misconfig (web targets only) ──────────────
        nuclei = None
        if has_web:
            nuclei = run_nuclei(target, tags=["tech", "ssl", "misconfig"])
            count  = nuclei.get("total", 0) if nuclei and not nuclei.get("error") else 0
            logger.info(f"[RECON] Nuclei done — {count} results")

        # ── Step 5: Email security (only if MX records found) ─────────────────
        email = None
        if dns["MX"].get("records"):
            email = {
                "dmarc": dns_lookup(f"_dmarc.{hostname}", "TXT"),
                "dkim":  dns_lookup(f"default._domainkey.{hostname}", "TXT"),
            }
            logger.info("[RECON] Email security DNS done")

        # ── Build structured context directly from tool output ─────────────────
        context = _build_context(hostname, scheme, dns, open_ports, nuclei)

        # ── Single LLM analysis pass ───────────────────────────────────────────
        findings = _analyse(self.llm, target, hostname, dns, nmap, tls, nuclei, email)
        elapsed  = round((datetime.utcnow() - start).total_seconds(), 2)

        logger.info(
            f"[RECON] Complete — {len(findings)} findings, "
            f"{len(open_ports)} open ports, {elapsed}s"
        )

        return {
            "module":           "recon",
            "target":           target,
            "hostname":         hostname,
            "ip_address":       context["ip_address"],
            "scheme":           context["scheme"],
            "host_type":        context["host_type"],
            "open_ports":       sorted(open_ports),
            "http_info":        context["http_info"],
            "technologies":     context["technologies"],
            "findings":         _normalise_findings(findings, target),
            "tool_used":        "recon_agent_v2",
            "auth_used":        config.build_auth_summary() if config else "Unauthenticated",
            "scan_time":        elapsed,
            "agent_status":     "complete",
            "agent_iterations": 1,
            "agent_summary":    f"{len(findings)} findings identified",
        }


# ── Context builder ────────────────────────────────────────────────────────────

def _build_context(hostname: str, scheme: str, dns: dict,
                   open_ports: set, nuclei: dict) -> dict:
    """Build structured recon context directly from tool output. No log parsing."""
    ctx = {
        "ip_address":   None,
        "scheme":       scheme,
        "host_type":    "unknown",
        "http_info":    {},
        "technologies": [],
    }

    a_records = dns.get("A", {}).get("records", [])
    if a_records:
        ctx["ip_address"] = a_records[0]

    if open_ports & _WEB_PORTS or scheme in ("http", "https"):
        ctx["host_type"] = "web_application"
        ctx["scheme"]    = "https" if 443 in open_ports or scheme == "https" else "http"
    elif open_ports:
        ctx["host_type"] = "network_host"

    if nuclei and not nuclei.get("error"):
        techs = [
            f["name"] for f in nuclei.get("findings", [])
            if "tech" in f.get("tags", [])
        ]
        ctx["technologies"] = list(dict.fromkeys(techs))

    return ctx


# ── LLM analysis ──────────────────────────────────────────────────────────────

def _analyse(llm, target, hostname, dns, nmap, tls, nuclei, email) -> list:
    """Send all collected recon data to the LLM in a single call."""
    payload = _build_payload(target, hostname, dns, nmap, tls, nuclei, email)
    user    = (
        f"Analyse this reconnaissance data and report all security findings:\n\n"
        f"{json.dumps(payload, indent=2)}"
    )
    response = llm.chat_json(_ANALYSIS_SYSTEM, user, max_tokens=2048)
    if not response:
        logger.warning("[RECON] LLM analysis returned no response")
        return []
    if isinstance(response, list):
        return response
    if isinstance(response, dict):
        # Handle {"findings": [...]} or unwrap the first list value
        for v in response.values():
            if isinstance(v, list):
                return v
    return []


def _build_payload(target, hostname, dns, nmap, tls, nuclei, email) -> dict:
    """Compact, LLM-readable summary of all recon results."""
    payload: dict = {
        "target":   target,
        "hostname": hostname,
        "dns": {
            rtype: (res.get("records", []) or f"ERROR: {res.get('error')}")
            for rtype, res in dns.items()
        },
    }

    if nmap and not nmap.get("error"):
        payload["open_ports"] = [
            {
                "port":    p["port"],
                "service": p["service"],
                "version": p.get("version", ""),
            }
            for h in nmap.get("hosts", [])
            for p in h.get("ports", [])
        ]

    if tls and not tls.get("error"):
        cert = tls.get("certificate") or {}
        payload["tls"] = {
            "subject":        cert.get("subject", {}).get("commonName"),
            "expired":        cert.get("expired"),
            "days_left":      cert.get("days_left"),
            "weak_protocols": tls.get("weak_protocols", []),
            "cert_error":     tls.get("cert_error"),
        }

    if nuclei and not nuclei.get("error"):
        payload["nuclei"] = [
            {
                "name":        f["name"],
                "severity":    f["severity"],
                "matched_at":  f["matched_at"],
                "description": f.get("description", ""),
            }
            for f in nuclei.get("findings", [])[:_MAX_NUCLEI_FINDINGS]
        ]

    if email:
        payload["email_security"] = {
            "dmarc": email["dmarc"].get("records") or email["dmarc"].get("error"),
            "dkim":  email["dkim"].get("records")  or email["dkim"].get("error"),
            "spf":   dns.get("TXT", {}).get("records", []),
        }

    return payload


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_open_ports(nmap_result: dict) -> set:
    if not nmap_result or nmap_result.get("error"):
        return set()
    return {
        p["port"]
        for h in nmap_result.get("hosts", [])
        for p in h.get("ports", [])
    }


def _parse_target(target: str) -> tuple:
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target, parsed.scheme
    return target, "https"


# ── Finding normalisation ──────────────────────────────────────────────────────

def _normalise_findings(findings: list, target: str) -> list:
    """Convert LLM output to the format enrichment.py expects."""
    normalised = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        finding = dict(f)

        if "remediation" in finding:
            finding["solution"] = finding.pop("remediation")
        if "severity" in finding:
            finding["risk"] = finding.pop("severity")
        if "cwe_id" in finding:
            finding["cwe"] = finding.pop("cwe_id")

        refs = finding.pop("references", []) or []
        for ref in refs:
            if "CVE-" in ref.upper():
                m = re.search(r"CVE-\d{4}-\d+", ref, re.IGNORECASE)
                if m:
                    finding["cve"] = m.group().upper()
                    break

        if not finding.get("url"):
            evidence = finding.get("evidence") or {}
            finding["url"] = evidence.get("url") or target

        if not finding.get("type"):
            finding["type"] = _infer_type(finding.get("name", ""))

        normalised.append(finding)
    return normalised


def _infer_type(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("header", "csp", "hsts", "frame", "sniff", "referrer")):
        return "missing_security_header"
    if any(k in n for k in ("tls", "ssl", "cert", "https", "cipher")):
        return "ssl_error"
    if any(k in n for k in ("version", "banner", "disclosure", "leak", "expose")):
        return "information_disclosure"
    if any(k in n for k in ("spf", "dmarc", "dkim", "email")):
        return "missing_security_header"
    return "web_vulnerability"
