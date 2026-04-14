"""
Vulnerability Enrichment Module
Adds CVSS v3.1 scoring, exploitability metadata, analyst notes,
compliance tags, and deduplication to raw agent findings.
"""
import hashlib
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

CVSS_MAP = {
    "Critical": {"score": 9.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    "High":     {"score": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
    "Medium":   {"score": 5.3, "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"},
    "Low":      {"score": 3.1, "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"},
    "Info":     {"score": 0.0, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
    "Informational": {"score": 0.0, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
}

EXPLOIT_MAP = {
    "Critical":      {"exploitability": "Easily Exploitable",      "exploit_available": True,  "attack_complexity": "Low",    "privileges_required": "None"},
    "High":          {"exploitability": "Exploitable",              "exploit_available": True,  "attack_complexity": "Low",    "privileges_required": "None"},
    "Medium":        {"exploitability": "Moderately Exploitable",   "exploit_available": False, "attack_complexity": "Medium", "privileges_required": "Low"},
    "Low":           {"exploitability": "Difficult to Exploit",     "exploit_available": False, "attack_complexity": "High",   "privileges_required": "Low"},
    "Info":          {"exploitability": "Not Directly Exploitable", "exploit_available": False, "attack_complexity": "High",   "privileges_required": "High"},
    "Informational": {"exploitability": "Not Directly Exploitable", "exploit_available": False, "attack_complexity": "High",   "privileges_required": "High"},
}

COMPLIANCE_MAP = {
    "missing_security_header":  ["OWASP A05:2021", "PCI-DSS 6.2"],
    "insecure_cookie":          ["OWASP A02:2021", "PCI-DSS 6.2"],
    "web_vulnerability":        ["OWASP Top 10",   "NIST SP 800-53 SI-10"],
    "open_port":                ["CIS Controls 4.4","NIST SP 800-53 CM-7"],
    "vulnerable_version":       ["CVE Program",    "NIST SP 800-53 SI-2"],
    "auth_misconfiguration":    ["OWASP A07:2021", "CIS Controls 5.2"],
    "cloud_misconfiguration":   ["CIS AWS Benchmark","NIST CSF PR.AC"],
    "information_disclosure":   ["OWASP A05:2021", "PCI-DSS 6.5"],
    "ssl_error":                ["OWASP A02:2021", "PCI-DSS 4.1"],
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Informational": 5}


def enrich_findings(all_module_results: list) -> list:
    logger.info("[ENRICHMENT] Starting vulnerability enrichment...")
    enriched = []
    seen_ids = set()

    for module_result in all_module_results:
        module_name = module_result.get("module", "unknown")
        target = module_result.get("target", "")
        for finding in module_result.get("findings", []):
            enriched_finding = _enrich_single(finding, module_name, target)
            # Deduplicate by ID
            if enriched_finding["id"] not in seen_ids:
                seen_ids.add(enriched_finding["id"])
                enriched.append(enriched_finding)

    enriched.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "Info"), 99))
    logger.info(f"[ENRICHMENT] Enriched {len(enriched)} findings (deduplicated).")
    return enriched


def _enrich_single(finding: dict, module_name: str, target: str) -> dict:
    raw_risk = finding.get("risk", finding.get("risk_hint", "Info"))
    severity = _normalize_severity(raw_risk)
    cvss = CVSS_MAP.get(severity, CVSS_MAP["Info"])
    exploit = EXPLOIT_MAP.get(severity, EXPLOIT_MAP["Info"])
    ftype = finding.get("type", "unknown")

    return {
        "id":                    _generate_id(finding, module_name),
        "name":                  finding.get("name", _infer_name(finding)),
        "type":                  ftype,
        "module":                module_name,
        "target":                target,
        "severity":              severity,
        "cvss_score":            cvss["score"],
        "cvss_vector":           cvss["vector"],
        "exploitability":        exploit["exploitability"],
        "exploit_available":     exploit["exploit_available"],
        "attack_complexity":     exploit["attack_complexity"],
        "privileges_required":   exploit["privileges_required"],
        "description":           finding.get("description", ""),
        "solution":              finding.get("solution", ""),
        "url":                   finding.get("url", finding.get("host", target)),
        "port":                  finding.get("port"),
        "service":               finding.get("service"),
        "cve":                   finding.get("cve"),
        "cwe":                   finding.get("cwe"),
        "evidence":              finding.get("evidence", ""),
        "analyst_note":          _generate_analyst_note(finding, severity, module_name),
        "compliance":            finding.get("compliance", COMPLIANCE_MAP.get(ftype, [])),
        "enriched_at":           datetime.utcnow().isoformat(),
        "validation_status":     "pending",
        "validated_by":          None,
        "false_positive":        False,
    }


def _normalize_severity(raw: str) -> str:
    mapping = {
        "critical": "Critical", "high": "High",
        "medium": "Medium", "moderate": "Medium",
        "low": "Low", "info": "Info",
        "informational": "Info", "none": "Info",
    }
    return mapping.get(str(raw).lower(), "Info")


def _generate_id(finding: dict, module: str) -> str:
    key = f"{module}_{finding.get('name', '')}_{finding.get('url', finding.get('port', ''))}"
    return "FIND-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()


def _infer_name(finding: dict) -> str:
    if finding.get("type") == "open_port":
        return f"Open Port: {finding.get('port')}/{finding.get('service', 'unknown')}"
    return finding.get("type", "Unknown Finding").replace("_", " ").title()


def _generate_analyst_note(finding: dict, severity: str, module: str) -> str:
    ftype = finding.get("type", "")
    name = finding.get("name", "")
    port = finding.get("port", "")
    service = finding.get("service", "unknown")

    notes = {
        "open_port": (
            f"Port {port} ({service}) is exposed externally. "
            "Cross-reference CVE database for detected software version. "
            "Verify business justification before closing — some services are intentionally public."
        ),
        "missing_security_header": (
            f"Missing header: {name}. "
            "This is a low-effort, high-impact fix — add the header at the web server level "
            "(Nginx/Apache config or app middleware). No code changes typically required."
        ),
        "web_vulnerability": (
            f"Web vulnerability detected: {name}. "
            "Perform manual verification to confirm exploitability. "
            "Test in both authenticated and unauthenticated contexts."
        ),
        "cloud_misconfiguration": (
            f"Cloud misconfiguration in {finding.get('service', 'cloud')}: {name}. "
            "Cloud misconfigs are the leading cause of cloud data breaches. "
            "Remediate before any public deployment or production use."
        ),
        "insecure_cookie": (
            f"Cookie security issue: {name}. "
            "If this cookie holds a session token, the effective severity is higher than rated. "
            "Verify the cookie's purpose and what data it carries."
        ),
        "ssl_error": (
            "SSL/TLS issue detected. Will cause browser trust warnings and may break mobile apps. "
            "Prioritise certificate remediation — Let's Encrypt provides free valid certificates."
        ),
        "auth_misconfiguration": (
            f"Authentication misconfiguration: {name}. "
            "Attempt manual verification (default credential test). "
            "If confirmed, treat as Critical regardless of base rating."
        ),
        "vulnerable_version": (
            f"Outdated/vulnerable version detected: {name}. "
            f"CVE: {finding.get('cve', 'unknown')}. "
            "Check vendor advisory for patch availability. Apply immediately for Critical/High CVEs."
        ),
        "information_disclosure": (
            f"Information disclosure: {name}. "
            "While often rated Low, this can enable targeted exploitation of other vulnerabilities. "
            "Suppress verbose error messages and version strings in production."
        ),
    }

    return notes.get(ftype, (
        f"Finding: '{name}' detected by {module} module. "
        f"Severity: {severity}. Manual verification recommended."
    ))
