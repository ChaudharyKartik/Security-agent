"""
Cloud Agent
Wraps Prowler CLI for AWS/GCP/Azure checks.
Falls back to mock cloud misconfiguration findings for dev/demo use.
Outputs CIS-benchmark-mapped findings.
"""
import logging
import subprocess
import json
import os
from datetime import datetime

logger = logging.getLogger(__name__)

MOCK_CLOUD_FINDINGS = [
    {
        "name": "S3 Bucket Public Read Access Enabled",
        "type": "cloud_misconfiguration",
        "risk": "Critical",
        "service": "S3",
        "resource": "s3://example-data-bucket",
        "description": "An S3 bucket has public read access enabled. Anyone on the internet can read its contents.",
        "solution": "Remove public ACL. Set Block Public Access on the bucket. Audit bucket policies.",
        "compliance": ["CIS AWS 2.1.2", "PCI-DSS 1.3"],
    },
    {
        "name": "Root Account Has Active Access Keys",
        "type": "cloud_misconfiguration",
        "risk": "Critical",
        "service": "IAM",
        "resource": "arn:aws:iam::root",
        "description": "The AWS root account has active access keys. Root should never be used programmatically.",
        "solution": "Delete root access keys immediately. Use IAM roles and least-privilege users instead.",
        "compliance": ["CIS AWS 1.4", "AWS Well-Architected"],
    },
    {
        "name": "Security Group Allows Unrestricted SSH (0.0.0.0/0)",
        "type": "cloud_misconfiguration",
        "risk": "High",
        "service": "EC2",
        "resource": "sg-0abc123def456",
        "description": "Security group allows SSH (port 22) from any IP address (0.0.0.0/0).",
        "solution": "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.",
        "compliance": ["CIS AWS 5.2", "PCI-DSS 1.2"],
    },
    {
        "name": "CloudTrail Logging Disabled",
        "type": "cloud_misconfiguration",
        "risk": "High",
        "service": "CloudTrail",
        "resource": "us-east-1",
        "description": "CloudTrail is not enabled in this region. API activity is not being logged.",
        "solution": "Enable CloudTrail with multi-region trails. Ensure S3 bucket log delivery is active.",
        "compliance": ["CIS AWS 3.1", "ISO 27001 A.12.4"],
    },
    {
        "name": "MFA Not Enabled for IAM Users with Console Access",
        "type": "cloud_misconfiguration",
        "risk": "High",
        "service": "IAM",
        "resource": "iam-user-admin",
        "description": "IAM users with console access do not have MFA enabled, increasing account takeover risk.",
        "solution": "Enforce MFA for all IAM users with console access. Use IAM policy to require MFA.",
        "compliance": ["CIS AWS 1.10", "NIST SP 800-53 IA-2"],
    },
    {
        "name": "RDS Instance Publicly Accessible",
        "type": "cloud_misconfiguration",
        "risk": "Critical",
        "service": "RDS",
        "resource": "db-prod-mysql",
        "description": "RDS database instance is publicly accessible from the internet.",
        "solution": "Disable public accessibility. Move RDS to a private subnet. Use VPC security groups.",
        "compliance": ["CIS AWS 2.3.2", "PCI-DSS 6.4"],
    },
    {
        "name": "EBS Snapshots Are Public",
        "type": "cloud_misconfiguration",
        "risk": "High",
        "service": "EBS",
        "resource": "snap-0abc123def456",
        "description": "EBS snapshots are publicly shared, potentially exposing sensitive data.",
        "solution": "Change snapshot visibility to private. Audit all public snapshots.",
        "compliance": ["CIS AWS 2.2.1"],
    },
    {
        "name": "VPC Flow Logs Not Enabled",
        "type": "cloud_misconfiguration",
        "risk": "Medium",
        "service": "VPC",
        "resource": "vpc-0abc123def456",
        "description": "VPC flow logs are disabled. Network traffic is not being recorded for forensic purposes.",
        "solution": "Enable VPC flow logs. Store in S3 or CloudWatch Logs with appropriate retention.",
        "compliance": ["CIS AWS 3.9"],
    },
]


def run_cloud_scan(target: str) -> dict:
    logger.info(f"[CLOUD] Starting cloud scan for: {target}")
    start = datetime.utcnow()

    provider = _detect_provider(target)
    prowler_result = _try_prowler(provider)

    if prowler_result:
        findings = prowler_result
        source = "prowler"
    else:
        logger.info("[CLOUD] Prowler unavailable — using mock cloud findings")
        findings = MOCK_CLOUD_FINDINGS.copy()
        source = "mock"

    result = {
        "module": "cloud",
        "target": target,
        "provider": provider,
        "source": source,
        "scan_time": (datetime.utcnow() - start).total_seconds(),
        "findings": findings,
    }
    logger.info(f"[CLOUD] Done. Source: {source} | Findings: {len(findings)}")
    return result


def _detect_provider(target: str) -> str:
    t = target.lower()
    if any(kw in t for kw in ["aws", "amazon", "s3", "ec2", "cloudfront", "elasticbeanstalk"]):
        return "aws"
    if any(kw in t for kw in ["azure", "blob.core", "microsoftonline"]):
        return "azure"
    if any(kw in t for kw in ["gcp", "google", "appspot", "googleapis"]):
        return "gcp"
    return "aws"  # default


def _try_prowler(provider: str) -> list | None:
    try:
        result = subprocess.run(
            ["prowler", provider, "--output-formats", "json", "-q"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None

        raw = json.loads(result.stdout)
        findings = []
        for item in raw:
            status = item.get("Status", "").upper()
            if status in ("FAIL", "CRITICAL", "HIGH"):
                findings.append({
                    "name": item.get("CheckTitle", "Cloud Check"),
                    "type": "cloud_misconfiguration",
                    "risk": _prowler_severity(item.get("Severity", "medium")),
                    "service": item.get("ServiceName", ""),
                    "resource": item.get("ResourceId", ""),
                    "description": item.get("StatusExtended", item.get("Description", "")),
                    "solution": item.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                    "compliance": _prowler_compliance(item),
                })
        return findings if findings else None
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return None


def _prowler_severity(s: str) -> str:
    return {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "informational": "Info"}.get(s.lower(), "Medium")


def _prowler_compliance(item: dict) -> list:
    refs = []
    for framework, checks in item.get("Compliance", {}).items():
        if isinstance(checks, list):
            refs.extend([f"{framework} {c}" for c in checks])
        elif checks:
            refs.append(str(framework))
    return refs
