"""
Cloud Agent — Prowler 5.x wrapper (AWS/GCP/Azure) with mock fallback.
Prowler 5.x outputs OCSF JSON to a file; we write to a temp dir and parse it.
Tool label: Prowler 5.x (real) | Mock Cloud Scanner (fallback)
"""
import json
import logging
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from glob import glob

logger = logging.getLogger(__name__)

TOOL_PROWLER  = "Prowler 5.x"
TOOL_FALLBACK = "Mock Cloud Scanner"

MOCK_FINDINGS = [
    {"name":"S3 Bucket Public Read Access","type":"cloud_misconfiguration","risk":"Critical",
     "service":"S3","resource":"s3://[target-bucket]","url":"s3://[target-bucket]",
     "description":"S3 bucket has public read access — anyone can read its contents. (Demo finding — Prowler not available)",
     "solution":"Remove public ACL. Enable Block Public Access.",
     "compliance":["CIS AWS 2.1.2","PCI-DSS 1.3"],
     "evidence":{"type":"cloud_check_demo","tool":"Demo"}},
    {"name":"Root Account Has Active Access Keys","type":"cloud_misconfiguration","risk":"Critical",
     "service":"IAM","resource":"arn:aws:iam::root","url":"arn:aws:iam::root",
     "description":"AWS root account has active access keys — should never be used programmatically. (Demo finding — Prowler not available)",
     "solution":"Delete root access keys. Use IAM roles and least-privilege users.",
     "compliance":["CIS AWS 1.4"],
     "evidence":{"type":"cloud_check_demo","tool":"Demo"}},
    {"name":"Security Group: SSH Open to 0.0.0.0/0","type":"cloud_misconfiguration","risk":"High",
     "service":"EC2","resource":"[security-group-id]","url":"[security-group-id]",
     "description":"Security group allows SSH (port 22) from any IP — brute force and exposure risk. (Demo finding — Prowler not available)",
     "solution":"Restrict SSH to specific IP ranges. Use AWS SSM Session Manager instead.",
     "compliance":["CIS AWS 5.2","PCI-DSS 1.2"],
     "evidence":{"type":"cloud_check_demo","tool":"Demo"}},
    {"name":"CloudTrail Logging Disabled","type":"cloud_misconfiguration","risk":"High",
     "service":"CloudTrail","resource":"us-east-1","url":"aws:cloudtrail:us-east-1",
     "description":"CloudTrail not enabled in this region — API activity not logged. (Demo finding — Prowler not available)",
     "solution":"Enable multi-region CloudTrail. Ensure S3 log delivery is active.",
     "compliance":["CIS AWS 3.1"],
     "evidence":{"type":"cloud_check_demo","tool":"Demo"}},
    {"name":"MFA Not Enabled for IAM Console Users","type":"cloud_misconfiguration","risk":"High",
     "service":"IAM","resource":"[iam-user]","url":"aws:iam:[target-user]",
     "description":"IAM users with console access don't have MFA — account takeover risk. (Demo finding — Prowler not available)",
     "solution":"Enforce MFA for all console users via IAM policy.",
     "compliance":["CIS AWS 1.10","NIST SP 800-53 IA-2"],
     "evidence":{"type":"cloud_check_demo","tool":"Demo"}},
    {"name":"RDS Instance Publicly Accessible","type":"cloud_misconfiguration","risk":"Critical",
     "service":"RDS","resource":"[rds-instance]","url":"aws:rds:[target-instance]",
     "description":"RDS database instance publicly accessible from the internet. (Demo finding — Prowler not available)",
     "solution":"Disable PubliclyAccessible. Move RDS to private subnet.",
     "compliance":["CIS AWS 2.3.2","PCI-DSS 6.4"],
     "evidence":{"type":"cloud_check_demo","tool":"Demo"}},
]


def run_cloud_scan(target: str, config=None, checklist_items=None) -> dict:
    logger.info(f"[CLOUD] Starting cloud scan: {target}")
    start    = datetime.utcnow()
    provider = (config.cloud_provider if config else None) or _detect_provider(target)
    profile  = (config.aws_profile    if config else None)
    region   = (config.aws_region     if config else None) or "us-east-1"

    prowler_result = _try_prowler(provider, profile, region)
    if prowler_result is not None:
        findings  = prowler_result
        tool_used = TOOL_PROWLER
    else:
        logger.info("[CLOUD] Prowler unavailable or no findings — using mock cloud findings")
        findings  = MOCK_FINDINGS.copy()
        tool_used = TOOL_FALLBACK

    return {
        "module":    "cloud",
        "target":    target,
        "provider":  provider,
        "tool_used": tool_used,
        "scan_time": (datetime.utcnow() - start).total_seconds(),
        "findings":  findings,
        "auth_used": f"AWS profile: {profile or 'default'}" if provider == "aws" else provider,
    }


def _detect_provider(target: str) -> str:
    t = target.lower()
    if any(k in t for k in ["aws", "amazon", "s3", "ec2", "cloudfront"]): return "aws"
    if any(k in t for k in ["azure", "blob.core"]):                        return "azure"
    if any(k in t for k in ["gcp", "google", "appspot"]):                  return "gcp"
    return "aws"


def _prowler_cmd() -> list[str]:
    """
    Resolve the Prowler executable.
    Checks venv/Scripts/ first (common on Windows), then falls back to python -m prowler.
    """
    scripts_dir = os.path.dirname(sys.executable)
    candidate   = os.path.join(scripts_dir, "prowler.exe" if sys.platform == "win32" else "prowler")
    if os.path.isfile(candidate):
        return [candidate]
    return [sys.executable, "-m", "prowler"]


def _try_prowler(provider: str, profile: str, region: str) -> list | None:
    """
    Run Prowler 5.x and return parsed findings, or None on failure.
    Prowler 5.x writes OCSF JSON to a file; we use a temp directory.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            cmd = _prowler_cmd() + [
                provider,
                "-M", "json-ocsf",
                "-o", tmpdir,
                "--output-filename", "prowler_out",
                "--severity", "critical", "high", "medium",
            ]
            if profile: cmd += ["--profile", profile]
            if region:  cmd += ["--region",  region]

            env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
            r = subprocess.run(cmd, capture_output=True, timeout=900, env=env)
            if r.returncode not in (0, 3):  # 3 = findings found (non-zero exit in v5)
                logger.warning(f"[CLOUD] Prowler exited with code {r.returncode}")
                return None

            # Find the output file
            matches = glob(os.path.join(tmpdir, "**", "*.ocsf.json"), recursive=True)
            if not matches:
                logger.warning("[CLOUD] Prowler ran but produced no output file")
                return None

            with open(matches[0], encoding="utf-8") as f:
                raw = json.load(f)

            return _parse_ocsf(raw)

        except subprocess.TimeoutExpired:
            logger.error("[CLOUD] Prowler timed out (900s) — AWS scan took too long")
            return None
        except Exception as e:
            logger.error(f"[CLOUD] Prowler error: {e}", exc_info=True)
            return None


def _parse_ocsf(raw: list) -> list | None:
    """Parse Prowler 5.x OCSF JSON into the internal finding schema."""
    findings = []
    for item in raw:
        if item.get("status_code", "").upper() != "FAIL":
            continue

        resource  = (item.get("resources") or [{}])[0]
        res_id    = resource.get("uid") or resource.get("name") or ""
        region    = resource.get("region", "")
        check_id  = item.get("metadata", {}).get("event_code", "")
        service   = check_id.split("_")[0].upper() if check_id else "AWS"

        compliance = []
        for fw, refs in item.get("unmapped", {}).get("compliance", {}).items():
            if isinstance(refs, list):
                compliance.extend([f"{fw} {r}" for r in refs])
            else:
                compliance.append(fw)

        findings.append({
            "name":        item.get("finding_info", {}).get("title", check_id),
            "type":        "cloud_misconfiguration",
            "risk":        _sev(item.get("severity", "medium")),
            "service":     service,
            "resource":    res_id,
            "url":         res_id,
            "description": item.get("status_detail", item.get("message", "")),
            "solution":    item.get("remediation", {}).get("desc", ""),
            "compliance":  compliance[:10],  # cap list length
            "evidence":    {
                "type":     "prowler",
                "tool":     TOOL_PROWLER,
                "check_id": check_id,
                "region":   region,
            },
        })

    return findings if findings else None


def _sev(s: str) -> str:
    return {
        "critical":      "Critical",
        "high":          "High",
        "medium":        "Medium",
        "low":           "Low",
        "informational": "Info",
    }.get(s.lower(), "Medium")
