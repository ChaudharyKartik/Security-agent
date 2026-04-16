"""
Orchestrator Agent — v3 (Knowledge Agent integrated)

The key upgrade: _decide_modules() is GONE.
Module selection now comes from the KnowledgeAgent's ExecutionPlan.
The orchestrator dispatches whatever the checklist says, not what it guesses.

Scan modes supported:
  full       — all applicable tests for target domain
  checklist  — only user-selected tests from registry
  single     — exactly one test
  owasp      — OWASP/NIST standard coverage (fallback when no checklist)
"""
import logging
import concurrent.futures
from datetime import datetime
from dataclasses import asdict

from agents.knowledge_agent import KnowledgeAgent, ExecutionPlan, MODE_FULL
from modules.recon import run_recon
from modules.network_module import run_network_scan
from modules.web_module import run_web_scan
from modules.cloud_module import run_cloud_scan
from enrichment import enrich_findings

logger = logging.getLogger(__name__)

# Singleton registry — loaded once, shared across all scan sessions
_knowledge_agent = KnowledgeAgent()


class Orchestrator:
    """
    Orchestrates the full scan pipeline.

    Input:  target, scan_mode, requested_tests, credentials (ScanConfig)
    Output: session dict with enriched_findings, summary, execution_plan
    """

    def __init__(self, config=None):
        self.config = config
        self.ka     = _knowledge_agent

    def run(self, target: str, session_id: str,
            scan_mode: str = MODE_FULL,
            requested_tests: list = None,
            status_callback=None,
            db=None) -> dict:                       # db: SQLAlchemy Session (optional)

        start = datetime.utcnow()
        auth_summary = self.config.build_auth_summary() if self.config else "Unauthenticated"
        logger.info(f"[ORCHESTRATOR] Session {session_id} | target={target} | "
                    f"mode={scan_mode} | tests={requested_tests} | auth={auth_summary}")

        session = {
            "session_id":        session_id,
            "target":            target,
            "scan_mode":         scan_mode,
            "requested_tests":   requested_tests or [],
            "start_time":        start.isoformat(),
            "end_time":          None,
            "duration_seconds":  None,
            "agents_executed":   [],
            "raw_results":       {},
            "enriched_findings": [],
            "summary":           {},
            "execution_plan":    {},
            "status":            "running",
            "error":             None,
            "auth_used":         auth_summary,
        }

        def _set(s):
            session["status"] = s
            if status_callback:
                status_callback(session_id, s)
            # Persist status update to DB if available
            if db:
                try:
                    from database import crud
                    crud.update_session_status(db, session_id, s)
                except Exception as e:
                    logger.warning(f"[DB] Status update failed: {e}")
            logger.info(f"[ORCHESTRATOR] [{session_id}] Status -> {s}")

        # Create the DB record now (before anything can fail)
        if db:
            try:
                from database import crud
                crud.create_session(db, session)
            except Exception as e:
                logger.warning(f"[DB] Session create failed: {e}")

        try:
            # ── Phase 1: Recon ─────────────────────────────────────────────────
            _set("recon")
            recon = run_recon(target, self.config)
            session["raw_results"]["recon"] = recon
            session["agents_executed"].append("recon_agent")

            # ── Phase 2: Knowledge Agent resolves the execution plan ────────────
            _set("knowledge_resolution")
            domain_hint = self._infer_domain(target, recon)
            plan: ExecutionPlan = self.ka.resolve(
                target         = target,
                mode           = scan_mode,
                requested_tests= requested_tests,
                domain_hint    = domain_hint,
            )
            session["execution_plan"] = {
                "scan_mode":      plan.scan_mode,
                "tests_resolved": len(plan.resolved_tests),
                "agents":         list(plan.agent_groups.keys()),
                "fallback_used":  plan.fallback_used,
                "resolution_log": plan.resolution_log,
                "tests": [
                    {
                        "id":             t.checklist_id,
                        "canonical_name": t.canonical_name,
                        "agent":          t.agent,
                        "domain":         t.domain,
                        "source":         t.source,
                        "fallback":       t.fallback,
                    }
                    for t in plan.resolved_tests
                ],
            }

            if not plan.resolved_tests:
                logger.warning(f"[ORCHESTRATOR] No tests resolved for mode={scan_mode}, "
                               f"tests={requested_tests}. Falling back to full scan.")
                plan = self.ka.resolve(target=target, mode=MODE_FULL,
                                       domain_hint=domain_hint)

            # ── Phase 3: Parallel agent dispatch ───────────────────────────────
            _set("scanning")
            module_results = self._dispatch_agents(target, recon, plan, session)

            # ── Phase 4: Enrichment ────────────────────────────────────────────
            # BUG FIX #1: Include recon findings in enrichment — previously they
            # were stored in raw_results["recon"] but never passed to enrich_findings(),
            # causing all recon-generated findings (missing headers, plain HTTP,
            # risky ports) to be silently dropped from the final output.
            _set("enrichment")
            all_results = [session["raw_results"]["recon"]] + module_results
            session["enriched_findings"] = enrich_findings(all_results)
            session["summary"]           = self._build_summary(
                session["enriched_findings"], session, plan)
            _set("awaiting_validation")

        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Fatal error: {e}", exc_info=True)
            session["status"] = "error"
            session["error"]  = str(e)
        finally:
            end = datetime.utcnow()
            session["end_time"]         = end.isoformat()
            session["duration_seconds"] = round((end - start).total_seconds(), 2)
            # Finalise DB record with findings and summary
            if db:
                try:
                    from database import crud
                    crud.finalise_session(db, session)
                    if session.get("enriched_findings"):
                        crud.save_findings(db, session_id, session["enriched_findings"])
                except Exception as e:
                    logger.warning(f"[DB] Finalise session failed: {e}")

        return session

    # ── Agent dispatch ─────────────────────────────────────────────────────────

    def _dispatch_agents(self, target: str, recon: dict,
                         plan: ExecutionPlan, session: dict) -> list:
        """
        Dispatch agents in parallel based on the execution plan.
        Each agent receives:
          - target
          - the list of ResolvedTest items assigned to it
          - ScanConfig credentials
          - recon data (context)
        """
        agent_groups = plan.agent_groups
        results      = []
        futures      = {}

        # Build task map — only include agents that have tests assigned.
        # BUG FIX #6: Lambdas now use default argument binding (i=items) to
        # capture the value of checklist_items at definition time rather than
        # closing over the mutable `agent_groups` dict by reference, which
        # would cause all lambdas to see the same (last) value if ever refactored.
        task_map = {}
        if "network_agent" in agent_groups:
            _items = agent_groups["network_agent"]
            task_map["network_agent"] = lambda i=_items: run_network_scan(
                target, recon, self.config,
                checklist_items=i
            )
        if "web_agent" in agent_groups:
            _items = agent_groups["web_agent"]
            task_map["web_agent"] = lambda i=_items: run_web_scan(
                target, self.config,
                checklist_items=i
            )
        # BUG FIX #4: Honor the run_cloud flag from ScanConfig — previously the
        # cloud agent was only dispatched when the Knowledge Agent resolved a
        # cloud_agent group (only for cloud-keyword targets). Now it also runs
        # whenever the user explicitly set run_cloud=True in the scan request.
        _run_cloud = self.config and getattr(self.config, "run_cloud", False)
        if "cloud_agent" in agent_groups or _run_cloud:
            _items = agent_groups.get("cloud_agent", [])
            task_map["cloud_agent"] = lambda i=_items: run_cloud_scan(
                target, self.config,
                checklist_items=i
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            for agent_name, task in task_map.items():
                future = ex.submit(task)
                futures[future] = agent_name
                _n = len(agent_groups.get(agent_name, []))
                logger.info(f"[ORCHESTRATOR] Dispatched: {agent_name} ({_n} tests)")

            for future in concurrent.futures.as_completed(futures):
                agent_name = futures[future]
                try:
                    result = future.result(timeout=300)
                    session["raw_results"][agent_name] = result
                    session["agents_executed"].append(agent_name)
                    results.append(result)
                    logger.info(f"[ORCHESTRATOR] {agent_name} completed — "
                                f"{len(result.get('findings', []))} findings | "
                                f"tool: {result.get('tool_used', '?')}")
                except concurrent.futures.TimeoutError:
                    logger.error(f"[ORCHESTRATOR] {agent_name} timed out (300s)")
                except Exception as e:
                    logger.error(f"[ORCHESTRATOR] {agent_name} failed: {e}",
                                 exc_info=True)

        return results

    # ── Domain inference ───────────────────────────────────────────────────────

    def _infer_domain(self, target: str, recon: dict) -> str:
        """
        Infer the primary domain for full/OWASP mode scans.
        The Knowledge Agent uses this to filter which tests to run.
        """
        host_type  = recon.get("host_type", "unknown")
        open_ports = {p["port"] for p in recon.get("open_ports", [])}
        t          = target.lower()

        CLOUD_KW = ["aws","amazon","azure","gcp","google","cloudfront","s3.","blob.core"]
        WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

        if any(kw in t for kw in CLOUD_KW):
            return "cloud"
        if host_type == "web_application" or open_ports & WEB_PORTS:
            return "web"
        return "network"

    # ── Summary ────────────────────────────────────────────────────────────────

    def _build_summary(self, enriched: list, session: dict,
                       plan: ExecutionPlan) -> dict:
        counts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for f in enriched:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        score = (counts["Critical"]*10 + counts["High"]*7 +
                 counts["Medium"]*4  + counts["Low"]*1)

        tools = {}
        for f in enriched:
            t = f.get("tool_used", "unknown")
            tools[t] = tools.get(t, 0) + 1

        # Map findings back to checklist items
        checklist_coverage = {}
        for test in plan.resolved_tests:
            checklist_coverage[test.canonical_name] = {
                "id":     test.checklist_id,
                "source": test.source,
                "findings": [
                    f["id"] for f in enriched
                    if f.get("checklist_id") == test.checklist_id
                ]
            }

        return {
            "total_findings":       len(enriched),
            "severity_breakdown":   counts,
            "overall_risk_score":   score,
            "risk_rating":          self._rating(score),
            "agents_run":           session["agents_executed"],
            "tool_breakdown":       tools,
            "scan_mode":            session["scan_mode"],
            "tests_planned":        len(plan.resolved_tests),
            "fallback_used":        plan.fallback_used,
            "checklist_coverage":   checklist_coverage,
            "scan_duration":        session.get("duration_seconds"),
        }

    @staticmethod
    def _rating(score: int) -> str:
        if score >= 50: return "CRITICAL"
        if score >= 25: return "HIGH"
        if score >= 10: return "MEDIUM"
        if score > 0:   return "LOW"
        return "CLEAN"
