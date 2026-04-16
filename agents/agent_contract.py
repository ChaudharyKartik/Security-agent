"""
Agent Contract — Layer 2

Every agent (web, network, cloud) receives an AgentInput and returns an AgentOutput.
This is the strict boundary that makes this an agent system, not a script.

Before Layer 2: run_web_scan(target, config) → raw dict
After Layer 2:  run_web_scan(AgentInput) → AgentOutput

The existing module functions are wrapped — no rewrite needed yet.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentInput:
    """
    Standardised input contract for every agent.
    The Orchestrator builds this and passes it to each agent.
    """
    target:          str
    checklist_items: list          # list[ResolvedTest] — what to test
    config:          object        # ScanConfig — credentials
    recon_data:      dict          # output from ReconAgent
    session_id:      str
    scan_mode:       str = "full"


@dataclass
class Finding:
    """
    Standardised finding object every agent MUST produce.
    Maps 1:1 to the finding schema in the PDF document.
    """
    # Identity
    name:            str
    type:            str           # open_port | web_vulnerability | auth_misconfiguration | etc.
    checklist_id:    Optional[str] = None
    canonical_name:  Optional[str] = None

    # Classification
    risk:            str = "Info"  # raw risk before CVSS enrichment
    cwe:             Optional[str] = None
    cve:             Optional[str] = None

    # Target context
    url:             Optional[str] = None
    port:            Optional[int] = None
    service:         Optional[str] = None
    host:            Optional[str] = None
    parameter:       Optional[str] = None
    method:          Optional[str] = None

    # Content
    description:     str = ""
    solution:        str = ""
    compliance:      list = field(default_factory=list)

    # Evidence (populated by Evidence Agent in Layer 5)
    evidence:        dict = field(default_factory=dict)
    # evidence = {
    #   "curl_poc":         "curl -sk ...",
    #   "request":          "RAW HTTP REQUEST",
    #   "response":         "RAW HTTP RESPONSE",
    #   "payload":          "<script>...",
    #   "response_snippet": "...",
    #   "type":             "missing_header | port_open | ...",
    # }

    # Confidence (set by FP Agent in Layer 5)
    confidence:      float = 1.0   # 0.0 - 1.0

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class AgentOutput:
    """
    Standardised output every agent MUST return.
    """
    agent:          str            # "web_agent" | "network_agent" | "cloud_agent"
    module:         str            # legacy compat: "web" | "network" | "cloud"
    target:         str
    tool_used:      str
    auth_used:      str
    scan_time:      float
    findings:       list           # list[dict] — Finding.to_dict() items
    checklist_items_tested: list   # canonical names that were tested
    raw_output:     dict = field(default_factory=dict)
    error:          Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}
