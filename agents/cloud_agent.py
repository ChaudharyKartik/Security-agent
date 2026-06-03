"""
CloudAgent — LLM-driven cloud security agent.

Replaces modules/cloud_module.py entirely, including its 6 hardcoded mock
findings. The LLM runs Prowler, evaluates FAIL findings by real-world risk,
and decides what is worth reporting and at what severity.

Returns a dict compatible with the orchestrator and enrichment pipeline.
"""
import logging
import os
import re
from datetime import datetime

from agents.base_agent import BaseAgent
from agents.tool_registry import build_registry
from agents.tools.prowler_tool import run_prowler
from agents.tools.http_tool import http_request
from agents.tools.finding_tool import report_finding

logger = logging.getLogger(__name__)

# ── System prompt (role + core rules only — sent on every LLM call) ───────────

_SYSTEM_PROMPT = (
    "You are a cloud security assessment agent. "
    "Do not report every Prowler FAIL — evaluate each for real exploitability. "
    "Prioritise: data exposure > privilege escalation > audit gaps > hygiene. "
    "Call done when all phases are complete."
)

# ── Methodology (sent once in the initial user message, not repeated per call) ─

_METHODOLOGY = """
PHASES:
1. AUDIT: run_prowler(provider, profile, region, services=["iam","s3","ec2","rds","cloudtrail","kms"])
2. EVALUATE each FAIL: exploitable without insider access? Data at risk? Privilege escalation possible? Or compliance-only?
3. FOLLOW-UP:
   S3 public: GET https://<bucket>.s3.amazonaws.com/ — 200+listing = Critical
   SG 0.0.0.0/0 on ports 22/3389/5432/3306 → escalate severity
   EC2 metadata without IMDSv2 → note it

FINDING TYPES: cloud_misconfiguration | auth_misconfiguration | information_disclosure | missing_security_header
SEVERITY: Critical=public_S3_data+public_RDS_no_auth+IAM_wildcard+hardcoded_creds | High=root_no_MFA+CloudTrail_off+S3_public_write+open_DB_SG | Medium=S3_logging_off+no_pw_policy+KMS_rotation_off | Low=minor_IAM_hygiene | Info=no_direct_exploit
EVIDENCE fields (all required): resource, region, check_id, observation, curl_poc"""

# ── Agent class ────────────────────────────────────────────────────────────────

class CloudAgent:
    """
    LLM-driven cloud security agent.
    Drop-in replacement for modules/cloud_module.run_cloud_scan().
    """

    def __init__(self, llm, scope: str = None):
        self.llm   = llm
        self.scope = scope

    def run(self, target: str, config=None, checklist_items=None, tool_filter=None) -> dict:
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
            max_iterations = int(os.getenv("CLOUD_MAX_ITERATIONS", "15")),
            scope          = self.scope or target,
        )

        goal = (
            f"Perform cloud security audit on: {target}\n"
            f"Provider: {provider}"
            + (f" | Profile: {profile}" if profile else "")
            + (f" | Region: {region}"   if region  else "")
            + f"\nAuth: {config.build_auth_summary() if config else 'Unauthenticated'}"
            + extra_context
            + _METHODOLOGY
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
