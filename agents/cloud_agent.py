"""
CloudAgent — LLM-driven cloud security agent.

Replaces modules/cloud_module.py entirely, including its 6 hardcoded mock
findings. The LLM runs Prowler, evaluates FAIL findings by real-world risk,
and decides what is worth reporting and at what severity.

Returns a dict compatible with the orchestrator and enrichment pipeline.
"""
import logging
import re
from datetime import datetime

from agents.base_agent import BaseAgent
from agents.tool_registry import build_registry
from agents.tools.prowler_tool import run_prowler
from agents.tools.http_tool import http_request
from agents.tools.finding_tool import report_finding

logger = logging.getLogger(__name__)

# ── System prompt ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a cloud security assessment agent. Your job is to audit cloud infrastructure for misconfigurations, over-permissive access, and compliance violations.

INVESTIGATION ORDER — work through each phase in sequence:

PHASE 1 — AUTOMATED CLOUD AUDIT
  run_prowler(provider, profile, region, services=["iam", "s3", "ec2", "rds", "cloudtrail", "kms"])
  - Start with high-impact services: IAM, S3, EC2, RDS
  - Review every FAIL finding: is this a real risk or a low-signal compliance checkbox?
  - Focus on findings that represent actual exploitable misconfigurations

PHASE 2 — EVALUATE PROWLER FINDINGS
  For each Prowler FAIL, ask:
  - Can an attacker exploit this without insider access?
  - Is data at risk (S3 public, RDS public, secrets exposed)?
  - Does this allow privilege escalation or lateral movement (IAM issues)?
  - Is this a compliance flag only (low practical risk)?

  Report only findings that represent real security risk. Skip pure compliance
  checkbox items with no practical exploitability.

PHASE 3 — TARGETED FOLLOW-UP (for AWS targets)
  For S3 findings: check if bucket is publicly accessible
  - http_request("GET", "https://<bucket-name>.s3.amazonaws.com/")
  - Confirm: 200 response with file listing = Critical

  For exposed metadata service indicators:
  - If EC2 instance metadata is accessible without IMDSv2, note it

  For exposed management interfaces:
  - If security groups allow 0.0.0.0/0 on admin ports (22, 3389, 5432, 3306),
    escalate severity

FINDING TYPES — always include `type` in report_finding():
  cloud_misconfiguration  — S3 public access, IAM over-permission, exposed RDS, weak KMS
  auth_misconfiguration   — root account usage, no MFA, over-permissive roles
  information_disclosure  — publicly accessible storage, exposed secrets
  missing_security_header — only if a web endpoint is involved

SEVERITY GUIDELINES:
  Critical: S3 bucket with sensitive data publicly readable, RDS instance publicly
            accessible with no auth, IAM wildcard permissions (*:*) on production role,
            hardcoded credentials in Lambda environment variables
  High:     Root account has no MFA, CloudTrail disabled, S3 bucket public with
            write access, security group allows all inbound traffic (0.0.0.0/0)
            on database ports, IAM policy allows privilege escalation
  Medium:   S3 bucket logging disabled, VPC flow logs disabled, no password policy,
            MFA not enforced for IAM users, KMS key rotation disabled,
            CloudWatch alarms not configured
  Low:      Minor IAM hygiene issues, unused access keys (< 90 days),
            non-critical compliance gaps
  Info:     Informational Prowler findings with no direct exploitability

EVIDENCE REQUIREMENTS — every report_finding() must include in evidence:
  resource    — affected cloud resource (ARN, bucket name, instance ID)
  region      — cloud region
  check_id    — Prowler check ID that flagged this
  observation — what Prowler found (description or risk field)
  curl_poc    — AWS CLI command or HTTP request that demonstrates the issue

IMPORTANT:
  - Do NOT report every Prowler FAIL — Prowler is noisy. Be selective.
  - Prioritise: data exposure > privilege escalation > audit gaps > hygiene
  - When all phases are complete, call done.
"""

# ── Agent class ────────────────────────────────────────────────────────────────

class CloudAgent:
    """
    LLM-driven cloud security agent.
    Drop-in replacement for modules/cloud_module.run_cloud_scan().
    """

    def __init__(self, llm, scope: str = None):
        self.llm   = llm
        self.scope = scope

    def run(self, target: str, config=None, checklist_items=None) -> dict:
        provider = _infer_provider(target, config)
        profile  = getattr(config, "aws_profile", None) if config else None
        region   = getattr(config, "aws_region",  None) if config else None

        registry = build_registry(run_prowler, http_request, report_finding)

        extra_context = ""
        if checklist_items:
            names = [getattr(t, "canonical_name", str(t)) for t in checklist_items]
            extra_context = f"\nFocus on these check categories: {', '.join(names)}"

        agent = BaseAgent(
            llm            = self.llm,
            tool_registry  = registry,
            system_prompt  = _SYSTEM_PROMPT,
            max_iterations = 40,
            scope          = self.scope or target,
        )

        goal = (
            f"Perform cloud security audit on: {target}\n"
            f"Provider: {provider}"
            + (f" | Profile: {profile}" if profile else "")
            + (f" | Region: {region}"   if region  else "")
            + extra_context + "\n"
            + f"Auth: {config.build_auth_summary() if config else 'Unauthenticated'}"
        )

        start  = datetime.utcnow()
        result = agent.run(
            goal    = goal,
            context = {"target": target, "provider": provider,
                       "profile": profile, "region": region},
        )
        elapsed = (datetime.utcnow() - start).total_seconds()

        logger.info(
            f"[CLOUD_AGENT] Done — {result.iterations} iterations, "
            f"{result.tool_call_count} tool calls, "
            f"{len(result.findings)} findings, "
            f"status={result.status}"
        )

        return {
            "module":           "cloud",
            "target":           target,
            "provider":         provider,
            "findings":         _normalise_findings(result.findings, target),
            "tool_used":        "ai_cloud_agent",
            "auth_used":        config.build_auth_summary() if config else "Unauthenticated",
            "scan_time":        elapsed,
            "agent_status":     result.status,
            "agent_iterations": result.iterations,
            "agent_summary":    result.summary,
        }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _infer_provider(target: str, config=None) -> str:
    """Infer cloud provider from target string or config."""
    if config and getattr(config, "cloud_provider", None):
        return config.cloud_provider.lower()
    t = target.lower()
    if any(k in t for k in ("azure", "blob.core", "windows.net")):
        return "azure"
    if any(k in t for k in ("gcp", "googleapis", "appspot", "google")):
        return "gcp"
    if any(k in t for k in ("k8s", "kubernetes")):
        return "kubernetes"
    return "aws"


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

        refs = finding.pop("references", []) or []
        for ref in refs:
            m = re.search(r"CVE-\d{4}-\d+", ref, re.IGNORECASE)
            if m:
                finding["cve"] = m.group().upper()
                break

        # Pull resource info from evidence for reporting
        evidence = finding.get("evidence") or {}
        if not finding.get("url"):
            resource = evidence.get("resource", "")
            finding["url"] = resource or target

        if not finding.get("type"):
            finding["type"] = _infer_type(finding.get("name", ""))

        normalised.append(finding)
    return normalised


def _infer_type(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("public", "exposed", "open", "unencrypted", "misconfigur")):
        return "cloud_misconfiguration"
    if any(k in n for k in ("mfa", "root", "credential", "password", "auth", "iam")):
        return "auth_misconfiguration"
    if any(k in n for k in ("secret", "key", "token", "disclosure", "leak")):
        return "information_disclosure"
    return "cloud_misconfiguration"
