"""
Knowledge Agent
The brain that resolves WHAT to test before any scanning begins.

Responsibilities:
  1. Load and validate the checklist registry
  2. Resolve user-requested tests to canonical checklist items
  3. Fall back to OWASP/NIST standard categories when no checklist item matches
  4. Group resolved tests by agent (web_agent, network_agent, cloud_agent)
  5. Return a structured execution plan the Orchestrator dispatches

This is what makes the system checklist-driven rather than just "scan everything".
"""
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "..", "checklist", "registry.json")

# Scan modes
MODE_FULL       = "full"         # run all applicable tests
MODE_CHECKLIST  = "checklist"    # run only specified checklist items
MODE_SINGLE     = "single"       # run exactly one test
MODE_OWASP      = "owasp"        # run OWASP coverage for a domain

VALID_MODES = {MODE_FULL, MODE_CHECKLIST, MODE_SINGLE, MODE_OWASP}


@dataclass
class ResolvedTest:
    """
    A single resolved test item ready for dispatch to an agent.
    This is the contract between the Knowledge Agent and the Orchestrator.
    """
    checklist_id:   str
    canonical_name: str
    domain:         str           # web | network | cloud
    agent:          str           # web_agent | network_agent | cloud_agent
    category:       str
    source:         str           # internal | owasp_wstg | nist | cis_aws
    owasp_ref:      Optional[str]
    cwe:            Optional[str]
    severity_default: str
    tools:          list
    test_steps:     list
    expected_evidence: list
    evidence_requirements: dict
    preconditions:  list
    remediation_ref: Optional[str]
    fallback:       bool = False   # True if resolved from OWASP/NIST, not internal checklist


@dataclass
class ExecutionPlan:
    """
    The full execution plan returned to the Orchestrator.
    Groups resolved tests by agent for parallel dispatch.
    """
    scan_mode:      str
    target:         str
    resolved_tests: list          # list[ResolvedTest]
    agent_groups:   dict = field(default_factory=dict)
    # {
    #   "web_agent":     [ResolvedTest, ...],
    #   "network_agent": [ResolvedTest, ...],
    #   "cloud_agent":   [ResolvedTest, ...],
    # }
    resolution_log: list = field(default_factory=list)  # audit trail of decisions
    fallback_used:  bool = False


class KnowledgeAgent:
    """
    Resolves test definitions. Called by the Orchestrator before dispatch.

    Usage:
        ka = KnowledgeAgent()
        plan = ka.resolve(
            target="https://example.com",
            mode="checklist",
            requested_tests=["SQL Injection", "XSS"]
        )
        # plan.agent_groups["web_agent"] = [ResolvedTest(...), ...]
    """

    def __init__(self, registry_path: str = REGISTRY_PATH):
        self.registry     = self._load_registry(registry_path)
        self._index       = self._build_index()
        self._alias_index = self._build_alias_index()
        logger.info(f"[KNOWLEDGE] Registry loaded: {len(self.registry['items'])} items")

    # ── Public API ─────────────────────────────────────────────────────────────

    def resolve(self, target: str, mode: str,
                requested_tests: list = None,
                domain_hint: str = None) -> ExecutionPlan:
        """
        Main entry point. Returns an ExecutionPlan.

        Args:
            target:          The scan target (URL or IP)
            mode:            full | checklist | single | owasp
            requested_tests: List of test names or IDs (for checklist/single modes)
            domain_hint:     "web" | "network" | "cloud" — filters full/owasp mode
        """
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid mode '{mode}'. Must be one of: {VALID_MODES}")

        logger.info(f"[KNOWLEDGE] Resolving: mode={mode}, target={target}, "
                    f"requested={requested_tests}, domain_hint={domain_hint}")

        plan = ExecutionPlan(scan_mode=mode, target=target, resolved_tests=[])

        if mode == MODE_SINGLE:
            plan = self._resolve_single(plan, requested_tests)
        elif mode == MODE_CHECKLIST:
            plan = self._resolve_checklist(plan, requested_tests)
        elif mode == MODE_FULL:
            plan = self._resolve_full(plan, domain_hint)
        elif mode == MODE_OWASP:
            plan = self._resolve_owasp(plan, domain_hint)

        # Group by agent
        plan.agent_groups = self._group_by_agent(plan.resolved_tests)

        logger.info(f"[KNOWLEDGE] Plan: {len(plan.resolved_tests)} tests resolved | "
                    f"agents: {list(plan.agent_groups.keys())} | "
                    f"fallback_used: {plan.fallback_used}")

        return plan

    def get_all_test_names(self) -> list:
        """Return all canonical names for UI dropdowns."""
        return [item["canonical_name"] for item in self.registry["items"]]

    def get_tests_by_domain(self, domain: str) -> list:
        """Return all canonical names for a given domain."""
        return [item["canonical_name"] for item in self.registry["items"]
                if item["domain"] == domain]

    def get_item_by_id(self, checklist_id: str) -> Optional[dict]:
        return self._index.get(checklist_id)

    def search(self, query: str) -> list:
        """Fuzzy search across names and aliases. Used by UI autocomplete."""
        q = query.lower().strip()
        results = []
        for item in self.registry["items"]:
            if (q in item["canonical_name"].lower() or
                    any(q in alias for alias in item.get("aliases", []))):
                results.append(item["canonical_name"])
        return results

    # ── Resolution modes ───────────────────────────────────────────────────────

    def _resolve_single(self, plan: ExecutionPlan, requested: list) -> ExecutionPlan:
        """Resolve exactly one test. Strict — fails if not found."""
        if not requested:
            raise ValueError("MODE_SINGLE requires exactly one test in requested_tests")

        name = requested[0] if isinstance(requested, list) else requested
        item = self._lookup(name)

        if item:
            plan.resolved_tests.append(self._to_resolved(item))
            plan.resolution_log.append(f"RESOLVED '{name}' -> {item['id']} (internal)")
        else:
            # Try OWASP fallback for the domain
            fallback = self._owasp_fallback_for_name(name)
            if fallback:
                plan.resolved_tests.append(fallback)
                plan.fallback_used = True
                plan.resolution_log.append(f"FALLBACK '{name}' -> OWASP category")
            else:
                plan.resolution_log.append(f"NOT FOUND '{name}' — skipped")
                logger.warning(f"[KNOWLEDGE] Test not found: '{name}'")

        return plan

    def _resolve_checklist(self, plan: ExecutionPlan, requested: list) -> ExecutionPlan:
        """Resolve a list of test names. Each resolved independently."""
        if not requested:
            raise ValueError("MODE_CHECKLIST requires at least one item in requested_tests")

        for name in requested:
            item = self._lookup(name)
            if item:
                plan.resolved_tests.append(self._to_resolved(item))
                plan.resolution_log.append(f"RESOLVED '{name}' -> {item['id']}")
            else:
                fallback = self._owasp_fallback_for_name(name)
                if fallback:
                    plan.resolved_tests.append(fallback)
                    plan.fallback_used = True
                    plan.resolution_log.append(f"FALLBACK '{name}' -> OWASP")
                else:
                    plan.resolution_log.append(f"NOT FOUND '{name}' — skipped")
                    logger.warning(f"[KNOWLEDGE] Skipping unknown test: '{name}'")

        return plan

    def _resolve_full(self, plan: ExecutionPlan, domain_hint: str = None) -> ExecutionPlan:
        """
        Resolve ALL tests from the registry regardless of domain.
        domain_hint is intentionally ignored here — full scan means full coverage.
        Domain filtering only applies in owasp mode.
        """
        for item in self.registry["items"]:
            plan.resolved_tests.append(self._to_resolved(item))
            plan.resolution_log.append(f"FULL SCAN: added {item['id']}")
        return plan

    def _resolve_owasp(self, plan: ExecutionPlan, domain: str = None) -> ExecutionPlan:
        """
        Resolve using OWASP/NIST standard categories as fallback.
        Used when domain has no internal checklist (e.g. pure network testing).
        """
        fallback_data = self.registry.get("owasp_fallback_categories", {})
        domains = [domain] if domain else list(fallback_data.keys())

        for d in domains:
            if d not in fallback_data:
                continue
            cats = fallback_data[d]
            # Map each OWASP category to internal tests where possible
            internal_for_domain = [i for i in self.registry["items"] if i["domain"] == d]
            if internal_for_domain:
                for item in internal_for_domain:
                    plan.resolved_tests.append(self._to_resolved(item))
                    plan.resolution_log.append(
                        f"OWASP MODE: {d} -> {item['id']} (internal match)")
            else:
                # Pure OWASP fallback — create generic test items
                for cat in cats["categories"]:
                    plan.resolved_tests.append(
                        self._make_owasp_fallback(cat, d, cats["source"]))
                plan.fallback_used = True
                plan.resolution_log.append(
                    f"OWASP MODE: {d} -> {len(cats['categories'])} standard categories (no internal)")

        return plan

    # ── Lookup helpers ─────────────────────────────────────────────────────────

    def _lookup(self, name: str) -> Optional[dict]:
        """
        Look up a test by:
        1. Exact canonical_name match
        2. Alias match
        3. ID match (CHK-001 style)
        """
        name_lower = name.lower().strip()

        # Exact canonical name
        for item in self.registry["items"]:
            if item["canonical_name"].lower() == name_lower:
                return item

        # Alias match
        if name_lower in self._alias_index:
            item_id = self._alias_index[name_lower]
            return self._index.get(item_id)

        # ID match
        name_upper = name.upper().strip()
        if name_upper in self._index:
            return self._index[name_upper]

        # Partial match (last resort — log warning)
        for item in self.registry["items"]:
            if name_lower in item["canonical_name"].lower():
                logger.warning(f"[KNOWLEDGE] Partial match: '{name}' -> '{item['canonical_name']}'")
                return item

        return None

    def _owasp_fallback_for_name(self, name: str) -> Optional[ResolvedTest]:
        """
        When a test name is not in the internal registry,
        create a generic OWASP-referenced test item.
        """
        name_lower = name.lower()
        # Guess domain from name keywords
        if any(k in name_lower for k in ["xss", "sql", "csrf", "idor", "web", "http", "cookie", "session", "header"]):
            domain, agent = "web", "web_agent"
            source = "OWASP WSTG v4.2"
        elif any(k in name_lower for k in ["port", "nmap", "network", "ssh", "ftp", "rdp", "ssl", "tls", "cipher"]):
            domain, agent = "network", "network_agent"
            source = "NIST SP 800-115"
        elif any(k in name_lower for k in ["aws", "cloud", "s3", "iam", "bucket", "azure", "gcp"]):
            domain, agent = "cloud", "cloud_agent"
            source = "CIS AWS Benchmark"
        else:
            return None  # Cannot map — skip

        return ResolvedTest(
            checklist_id    = f"FALLBACK-{hash(name) % 10000:04d}",
            canonical_name  = name,
            domain          = domain,
            agent           = agent,
            category        = "general",
            source          = source,
            owasp_ref       = None,
            cwe             = None,
            severity_default= "Medium",
            tools           = [],
            test_steps      = [f"Test for: {name}"],
            expected_evidence = [],
            evidence_requirements = {"request": True, "response": True,
                                     "payload": False, "screenshot": False},
            preconditions   = [],
            remediation_ref = None,
            fallback        = True,
        )

    def _make_owasp_fallback(self, category: str, domain: str, source: str) -> ResolvedTest:
        agent_map = {"web": "web_agent", "network": "network_agent", "cloud": "cloud_agent"}
        return ResolvedTest(
            checklist_id    = f"OWASP-{hash(category) % 10000:04d}",
            canonical_name  = category,
            domain          = domain,
            agent           = agent_map.get(domain, "web_agent"),
            category        = "owasp_standard",
            source          = source,
            owasp_ref       = None,
            cwe             = None,
            severity_default= "Medium",
            tools           = [],
            test_steps      = [f"Follow {source} guidance for: {category}"],
            expected_evidence = [],
            evidence_requirements = {"request": True, "response": True,
                                     "payload": False, "screenshot": False},
            preconditions   = [],
            remediation_ref = None,
            fallback        = True,
        )

    # ── Index builders ─────────────────────────────────────────────────────────

    def _build_index(self) -> dict:
        """Primary index: checklist ID -> item dict."""
        return {item["id"]: item for item in self.registry["items"]}

    def _build_alias_index(self) -> dict:
        """Alias index: lowercase alias -> checklist ID."""
        idx = {}
        for item in self.registry["items"]:
            for alias in item.get("aliases", []):
                idx[alias.lower()] = item["id"]
            # Also index the canonical name itself
            idx[item["canonical_name"].lower()] = item["id"]
        return idx

    def _group_by_agent(self, tests: list) -> dict:
        """Group resolved tests by their target agent."""
        groups = {}
        for test in tests:
            agent = test.agent
            if agent not in groups:
                groups[agent] = []
            groups[agent].append(test)
        return groups

    def _to_resolved(self, item: dict) -> ResolvedTest:
        """Convert registry dict to ResolvedTest dataclass."""
        return ResolvedTest(
            checklist_id     = item["id"],
            canonical_name   = item["canonical_name"],
            domain           = item["domain"],
            agent            = item["agent"],
            category         = item["category"],
            source           = item["source"],
            owasp_ref        = item.get("owasp_ref"),
            cwe              = item.get("cwe"),
            severity_default = item.get("severity_default", "Medium"),
            tools            = item.get("tools", []),
            test_steps       = item.get("test_steps", []),
            expected_evidence= item.get("expected_evidence", []),
            evidence_requirements = item.get("evidence_requirements",
                                             {"request":True,"response":True,
                                              "payload":False,"screenshot":False}),
            preconditions    = item.get("preconditions", []),
            remediation_ref  = item.get("remediation_ref"),
            fallback         = False,
        )

    @staticmethod
    def _load_registry(path: str) -> dict:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Checklist registry not found at: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "items" not in data:
            raise ValueError("Registry JSON must have an 'items' key")
        return data
