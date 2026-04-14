"""
Cloud Agent — Prowler wrapper (AWS/GCP/Azure) with mock fallback.
Tool label: Prowler 3.x (real) | Mock Cloud Scanner (fallback)
"""
import logging
import subprocess
import json
from datetime import datetime

logger = logging.getLogger(__name__)

TOOL_PROWLER  = "Prowler 3.x"
TOOL_FALLBACK = "Mock Cloud Scanner"

MOCK_FINDINGS = [
    {"name":"S3 Bucket Public Read Access","type":"cloud_misconfiguration","risk":"Critical",
     "service":"S3","resource":"s3://example-data-bucket",
     "description":"S3 bucket has public read access — anyone can read its contents.",
     "solution":"Remove public ACL. Enable Block Public Access.",
     "compliance":["CIS AWS 2.1.2","PCI-DSS 1.3"],
     "evidence":{"type":"cloud_check","curl_poc":'aws s3 ls s3://example-data-bucket --no-sign-request',"tool":"Prowler"}},
    {"name":"Root Account Has Active Access Keys","type":"cloud_misconfiguration","risk":"Critical",
     "service":"IAM","resource":"arn:aws:iam::root",
     "description":"AWS root account has active access keys — should never be used programmatically.",
     "solution":"Delete root access keys. Use IAM roles and least-privilege users.",
     "compliance":["CIS AWS 1.4"],
     "evidence":{"type":"cloud_check","curl_poc":'aws iam list-access-keys --user-name root',"tool":"Prowler"}},
    {"name":"Security Group: SSH Open to 0.0.0.0/0","type":"cloud_misconfiguration","risk":"High",
     "service":"EC2","resource":"sg-0abc123def456",
     "description":"Security group allows SSH (port 22) from any IP — brute force and exposure risk.",
     "solution":"Restrict SSH to specific IP ranges. Use AWS SSM Session Manager instead.",
     "compliance":["CIS AWS 5.2","PCI-DSS 1.2"],
     "evidence":{"type":"cloud_check","curl_poc":'aws ec2 describe-security-groups --group-ids sg-0abc123def456',"tool":"Prowler"}},
    {"name":"CloudTrail Logging Disabled","type":"cloud_misconfiguration","risk":"High",
     "service":"CloudTrail","resource":"us-east-1",
     "description":"CloudTrail not enabled in this region — API activity not logged.",
     "solution":"Enable multi-region CloudTrail. Ensure S3 log delivery is active.",
     "compliance":["CIS AWS 3.1"],
     "evidence":{"type":"cloud_check","curl_poc":'aws cloudtrail describe-trails',"tool":"Prowler"}},
    {"name":"MFA Not Enabled for IAM Console Users","type":"cloud_misconfiguration","risk":"High",
     "service":"IAM","resource":"iam-user-admin",
     "description":"IAM users with console access don't have MFA — account takeover risk.",
     "solution":"Enforce MFA for all console users via IAM policy.",
     "compliance":["CIS AWS 1.10","NIST SP 800-53 IA-2"],
     "evidence":{"type":"cloud_check","curl_poc":'aws iam list-virtual-mfa-devices',"tool":"Prowler"}},
    {"name":"RDS Instance Publicly Accessible","type":"cloud_misconfiguration","risk":"Critical",
     "service":"RDS","resource":"db-prod-mysql",
     "description":"RDS database instance publicly accessible from the internet.",
     "solution":"Disable PubliclyAccessible. Move RDS to private subnet.",
     "compliance":["CIS AWS 2.3.2","PCI-DSS 6.4"],
     "evidence":{"type":"cloud_check","curl_poc":'aws rds describe-db-instances --query "DBInstances[*].PubliclyAccessible"',"tool":"Prowler"}},
]


def run_cloud_scan(target: str, config=None) -> dict:
    logger.info(f"[CLOUD] Starting cloud scan: {target}")
    start    = datetime.utcnow()
    provider = (config.cloud_provider if config else None) or _detect_provider(target)
    profile  = (config.aws_profile    if config else None)
    region   = (config.aws_region     if config else None) or "us-east-1"

    prowler_result = _try_prowler(provider, profile, region)
    if prowler_result:
        findings   = prowler_result
        tool_used  = TOOL_PROWLER
    else:
        logger.info("[CLOUD] Prowler unavailable — using mock cloud findings")
        findings  = MOCK_FINDINGS.copy()
        tool_used = TOOL_FALLBACK

    return {
        "module":     "cloud",
        "target":     target,
        "provider":   provider,
        "tool_used":  tool_used,
        "scan_time":  (datetime.utcnow() - start).total_seconds(),
        "findings":   findings,
        "auth_used":  f"AWS profile: {profile or 'default'}" if provider == "aws" else provider,
    }


def _detect_provider(target: str) -> str:
    t = target.lower()
    if any(k in t for k in ["aws","amazon","s3","ec2","cloudfront"]): return "aws"
    if any(k in t for k in ["azure","blob.core"]):                    return "azure"
    if any(k in t for k in ["gcp","google","appspot"]):               return "gcp"
    return "aws"


def _try_prowler(provider: str, profile: str, region: str) -> list | None:
    try:
        cmd = ["prowler", provider, "--output-formats", "json", "-q"]
        if profile: cmd += ["--profile", profile]
        if region:  cmd += ["--region",  region]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode != 0 or not r.stdout.strip():
            return None
        raw = json.loads(r.stdout)
        findings = []
        for item in raw:
            if item.get("Status","").upper() in ("FAIL","CRITICAL","HIGH"):
                findings.append({
                    "name":        item.get("CheckTitle","Cloud Check"),
                    "type":        "cloud_misconfiguration",
                    "risk":        _sev(item.get("Severity","medium")),
                    "service":     item.get("ServiceName",""),
                    "resource":    item.get("ResourceId",""),
                    "description": item.get("StatusExtended", item.get("Description","")),
                    "solution":    item.get("Remediation",{}).get("Recommendation",{}).get("Text",""),
                    "compliance":  _compliance(item),
                    "evidence":    {"type":"prowler","tool":TOOL_PROWLER,"raw":str(item)[:300]},
                })
        return findings or None
    except Exception:
        return None


def _sev(s: str) -> str:
    return {"critical":"Critical","high":"High","medium":"Medium",
            "low":"Low","informational":"Info"}.get(s.lower(),"Medium")


def _compliance(item: dict) -> list:
    refs = []
    for fw, checks in item.get("Compliance",{}).items():
        if isinstance(checks, list):
            refs.extend([f"{fw} {c}" for c in checks])
        elif checks:
            refs.append(str(fw))
    return refs
