"""
CVSS v3.1 Calculator — Real dynamic scoring from metric inputs.
No hardcoded scores. Every finding gets a score derived from its
actual attack characteristics per the CVSS 3.1 specification.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""
import math
from dataclasses import dataclass
from typing import Literal

# ── Metric value weights per CVSS 3.1 spec ───────────────────────────────────

AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}   # Attack Vector
AC  = {"L": 0.77, "H": 0.44}                            # Attack Complexity
PR_no_scope  = {"N": 0.85, "L": 0.62, "H": 0.27}       # Privileges Required (unchanged scope)
PR_changed   = {"N": 0.85, "L": 0.68, "H": 0.50}       # Privileges Required (changed scope)
UI  = {"N": 0.85, "R": 0.62}                            # User Interaction
CIA = {"N": 0.00, "L": 0.22, "H": 0.56}                # Confidentiality / Integrity / Availability


@dataclass
class CVSSMetrics:
    """
    All 8 base metrics for CVSS v3.1.
    Values use the single-letter codes from the spec.
    """
    attack_vector:          Literal["N","A","L","P"] = "N"   # Network/Adjacent/Local/Physical
    attack_complexity:      Literal["L","H"]          = "L"   # Low/High
    privileges_required:    Literal["N","L","H"]      = "N"   # None/Low/High
    user_interaction:       Literal["N","R"]          = "N"   # None/Required
    scope:                  Literal["U","C"]          = "U"   # Unchanged/Changed
    confidentiality_impact: Literal["N","L","H"]      = "N"   # None/Low/High
    integrity_impact:       Literal["N","L","H"]      = "N"   # None/Low/High
    availability_impact:    Literal["N","L","H"]      = "N"   # None/Low/High


def calculate_cvss(metrics: CVSSMetrics) -> dict:
    """
    Compute CVSS v3.1 Base Score, Severity, and Vector String.
    Returns a dict with score, severity, vector, and all sub-scores.
    """
    scope_changed = metrics.scope == "C"

    # Exploitability sub-score
    pr_weight = PR_changed[metrics.privileges_required] if scope_changed \
                else PR_no_scope[metrics.privileges_required]
    iss_base = 1 - (
        (1 - CIA[metrics.confidentiality_impact]) *
        (1 - CIA[metrics.integrity_impact]) *
        (1 - CIA[metrics.availability_impact])
    )
    # Impact sub-score
    if scope_changed:
        iss = 7.52 * (iss_base - 0.029) - 3.25 * ((iss_base - 0.02) ** 15)
    else:
        iss = 6.42 * iss_base

    exploitability = (
        8.22 *
        AV[metrics.attack_vector] *
        AC[metrics.attack_complexity] *
        pr_weight *
        UI[metrics.user_interaction]
    )

    if iss <= 0:
        base_score = 0.0
    else:
        if scope_changed:
            raw = min(1.08 * (iss + exploitability), 10)
        else:
            raw = min(iss + exploitability, 10)
        base_score = _roundup(raw)

    severity = _score_to_severity(base_score)
    vector   = _build_vector(metrics)

    return {
        "score":             base_score,
        "severity":          severity,
        "vector":            vector,
        "exploitability_score": round(exploitability, 2),
        "impact_score":         round(iss, 2),
        "metrics": {
            "AV": metrics.attack_vector,
            "AC": metrics.attack_complexity,
            "PR": metrics.privileges_required,
            "UI": metrics.user_interaction,
            "S":  metrics.scope,
            "C":  metrics.confidentiality_impact,
            "I":  metrics.integrity_impact,
            "A":  metrics.availability_impact,
        }
    }


def cvss_from_finding_type(finding_type: str, finding: dict) -> CVSSMetrics:
    """
    Derive CVSS metrics from a finding's type and properties.
    This replaces the static CVSS_MAP lookup in enrichment.py.
    Each type gets realistic metric assignments based on how
    that class of vulnerability is actually exploited.
    """
    port    = finding.get("port")
    service = (finding.get("service") or "").lower()

    profiles = {
        # Web vulns - network reachable, often low complexity
        "web_vulnerability": CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="R",
            scope="U",
            confidentiality_impact="L", integrity_impact="L", availability_impact="N"
        ),
        # Missing headers - low direct impact but enables other attacks
        "missing_security_header": CVSSMetrics(
            attack_vector="N", attack_complexity="H",
            privileges_required="N", user_interaction="R",
            scope="U",
            confidentiality_impact="L", integrity_impact="N", availability_impact="N"
        ),
        # Insecure cookies - session hijack possible
        "insecure_cookie": CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="R",
            scope="U",
            confidentiality_impact="H", integrity_impact="L", availability_impact="N"
        ),
        # SSL/TLS - MITM risk
        "ssl_error": CVSSMetrics(
            attack_vector="N", attack_complexity="H",
            privileges_required="N", user_interaction="N",
            scope="U",
            confidentiality_impact="H", integrity_impact="L", availability_impact="N"
        ),
        # Open ports - depends on service; set moderate defaults
        "open_port": CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U",
            confidentiality_impact="L", integrity_impact="N", availability_impact="N"
        ),
        # Auth misconfigs - direct account compromise
        "auth_misconfiguration": CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="C",
            confidentiality_impact="H", integrity_impact="H", availability_impact="H"
        ),
        # Vulnerable versions - typically RCE or critical data exposure
        "vulnerable_version": CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="C",
            confidentiality_impact="H", integrity_impact="H", availability_impact="H"
        ),
        # Cloud misconfigs - high blast radius
        "cloud_misconfiguration": CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="C",
            confidentiality_impact="H", integrity_impact="H", availability_impact="L"
        ),
        # Info disclosure - low direct impact
        "information_disclosure": CVSSMetrics(
            attack_vector="N", attack_complexity="L",
            privileges_required="N", user_interaction="N",
            scope="U",
            confidentiality_impact="L", integrity_impact="N", availability_impact="N"
        ),
    }

    base = profiles.get(finding_type, CVSSMetrics())

    # Tune open_port based on specific service risk
    if finding_type == "open_port":
        high_risk_services = {"telnet", "ftp", "rdp", "vnc", "smb", "rsh", "rlogin"}
        critical_services  = {"redis", "mongodb", "elasticsearch"}
        if service in critical_services:
            base.confidentiality_impact = "H"
            base.integrity_impact       = "H"
            base.privileges_required    = "N"
        elif service in high_risk_services:
            base.confidentiality_impact = "H"
            base.integrity_impact       = "L"

    return base


# ── Helpers ───────────────────────────────────────────────────────────────────

def _roundup(x: float) -> float:
    """CVSS 3.1 roundup: ceil to nearest 0.1"""
    return math.ceil(x * 10) / 10


def _score_to_severity(score: float) -> str:
    if score == 0.0:   return "Info"
    if score < 4.0:    return "Low"
    if score < 7.0:    return "Medium"
    if score < 9.0:    return "High"
    return "Critical"


def _build_vector(m: CVSSMetrics) -> str:
    return (
        f"CVSS:3.1/AV:{m.attack_vector}/AC:{m.attack_complexity}"
        f"/PR:{m.privileges_required}/UI:{m.user_interaction}"
        f"/S:{m.scope}/C:{m.confidentiality_impact}"
        f"/I:{m.integrity_impact}/A:{m.availability_impact}"
    )


# ── Convenience: parse vector string back to score ───────────────────────────

def score_from_vector(vector: str) -> dict:
    """Parse a CVSS:3.1/... vector string and return calculate_cvss result."""
    try:
        parts = {}
        for segment in vector.replace("CVSS:3.1/", "").split("/"):
            k, v = segment.split(":")
            parts[k] = v
        m = CVSSMetrics(
            attack_vector=parts["AV"],
            attack_complexity=parts["AC"],
            privileges_required=parts["PR"],
            user_interaction=parts["UI"],
            scope=parts["S"],
            confidentiality_impact=parts["C"],
            integrity_impact=parts["I"],
            availability_impact=parts["A"],
        )
        return calculate_cvss(m)
    except Exception:
        return {"score": 0.0, "severity": "Info", "vector": vector}
