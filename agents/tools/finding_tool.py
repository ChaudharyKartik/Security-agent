"""
finding_tool — report_finding() is the output contract for all LLM agents.

BaseAgent intercepts calls to this tool before the function body executes —
it validates the schema and captures the finding internally. The function
here exists so that:
  1. _get_tool_schemas() picks up __schema__ for the LLM tool list.
  2. Standalone tests can call it directly to verify the schema is sensible.

Required fields: name, severity, evidence, remediation
Optional fields: description, cvss_score, cwe_id, references
"""
from typing import Optional

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def report_finding(
    name:        str,
    severity:    str,
    evidence:    dict,
    remediation: str,
    description: str            = "",
    cvss_score:  Optional[float]= None,
    cwe_id:      str            = "",
    references:  list           = None,
) -> dict:
    """
    Report a confirmed vulnerability finding.
    Called by the LLM agent when it has sufficient evidence of a real finding.
    """
    if severity not in VALID_SEVERITIES:
        return {
            "status": "rejected",
            "reason": f"Invalid severity '{severity}'. Must be one of: {VALID_SEVERITIES}",
        }
    missing = [f for f in ("name", "evidence", "remediation")
               if not locals().get(f)]
    if missing:
        return {"status": "rejected", "reason": f"Missing required fields: {missing}"}

    return {
        "status":      "accepted",
        "name":        name,
        "severity":    severity,
        "description": description,
        "evidence":    evidence,
        "remediation": remediation,
        "cvss_score":  cvss_score,
        "cwe_id":      cwe_id,
        "references":  references or [],
    }


report_finding.__schema__ = {
    "name": "report_finding",
    "description": (
        "Report a confirmed vulnerability finding. Call this only when you have "
        "concrete evidence — a real HTTP response, a successful payload, or "
        "observed server behaviour that confirms the issue. Do NOT call this for "
        "suspected or theoretical issues."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Short, descriptive finding title (e.g. 'Reflected XSS in search parameter').",
            },
            "severity": {
                "type": "string",
                "enum": list(VALID_SEVERITIES),
                "description": "Severity based on exploitability and impact.",
            },
            "evidence": {
                "type": "object",
                "description": (
                    "Concrete evidence dict. Include: url, request (method + headers + body), "
                    "response (status + relevant snippet), curl_poc (copy-paste PoC command). "
                    "All fields are free-form strings."
                ),
            },
            "remediation": {
                "type": "string",
                "description": "Specific, actionable remediation steps for the developer.",
            },
            "description": {
                "type": "string",
                "description": "Optional technical explanation of the vulnerability and its impact.",
            },
            "cvss_score": {
                "type": "number",
                "description": "Optional CVSS v3.1 base score (0.0–10.0).",
            },
            "cwe_id": {
                "type": "string",
                "description": "Optional CWE identifier (e.g. 'CWE-79').",
            },
            "references": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of reference URLs (OWASP, CVE, etc.).",
            },
            "type": {
                "type": "string",
                "enum": [
                    "missing_security_header", "ssl_error", "information_disclosure",
                    "web_vulnerability", "open_port", "vulnerable_version",
                    "auth_misconfiguration", "cloud_misconfiguration", "insecure_cookie",
                    "sql_injection", "command_injection", "xss_reflected", "xss_stored",
                    "path_traversal", "idor", "ssrf", "csrf", "open_redirect",
                    "cors_misconfiguration",
                ],
                "description": "Finding type — used for CVSS mapping and compliance tagging.",
            },
            "url": {
                "type": "string",
                "description": "Affected URL or endpoint.",
            },
        },
        "required": ["name", "severity", "evidence", "remediation"],
    },
}
