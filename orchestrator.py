"""
Orchestrator — v4 (AI-driven agents, no Knowledge Agent)

Agents are LLM-driven and self-direct their testing. The orchestrator's only
job is to sequence them and collect results. No security logic lives here.

Scan modes:
  full       — all applicable agents for the detected domain
  owasp      — same as full (OWASP coverage is now the agent's responsibility)
  checklist  — pass requested_tests as focus hints to agents
  single     — run the single most relevant agent with the requested test as goal
"""
import logging
import concurrent.futures
from datetime import datetime

from agents.fp_agent import analyse_findings
from agents.reviewer_agent import ReviewerAgent
from agents.recon_agent import ReconAgent
from agents.web_agent import WebAgent
from agents.network_agent import NetworkAgent
from agents.cloud_agent import CloudAgent
from agents.llm_client import get_llm
from enrichment import enrich_findings
from database import crud

logger = logging.getLogger(__name__)

# Singletons — loaded once, shared across all scan sessions
_reviewer_agent = ReviewerAgent()
_recon_agent    = ReconAgent(llm=get_llm())
_web_agent      = WebAgent(llm=get_llm())
_network_agent  = NetworkAgent(llm=get_llm())
_cloud_agent    = CloudAgent(llm=get_llm())


class Orchestrator:
    """
    Sequences the scan pipeline. No security logic — agents handle that.

    Input:  target, scan_mode, requested_tests, credentials (ScanConfig)
    Output: session dict with enriched_findings, summary, execution_plan
    """

    def __init__(self, config=None):
        self.config = config

    def run(self, target: str, session_id: str,
            scan_mode: str = "full",
            requested_tests: list = None,
            status_callback=None,
            db=None) -> dict:

        start        = datetime.utcnow()
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
            if db:
                try:
                    crud.update_session_status(db, session_id, s)
                except Exception as e:
                    logger.warning(f"[DB] Status update failed: {e}")
            logger.info(f"[ORCHESTRATOR] [{session_id}] Status -> {s}")

        if db:
            try:
                crud.create_session(db, session)
            except Exception as e:
                logger.warning(f"[DB] Session create failed: {e}")

        try:
            # ── Phase 1: Recon ─────────────────────────────────────────────────
            _set("recon")
            recon = _recon_agent.run(target, self.config)
            session["raw_results"]["recon"] = recon
            session["agents_executed"].append("recon_agent")

            # ── Phase 2: Agent selection (replaces Knowledge Agent) ────────────
            _set("scanning")
            domain       = self._infer_domain(target, recon)
            agent_groups = self._select_agents(domain, scan_mode, requested_tests)

            session["execution_plan"] = {
                "scan_mode":    scan_mode,
                "domain":       domain,
                "agents":       list(agent_groups.keys()),
                "focus_tests":  requested_tests or [],
            }
            logger.info(f"[ORCHESTRATOR] Domain={domain} | agents={list(agent_groups.keys())}")

            # ── Phase 3: Parallel agent dispatch ───────────────────────────────
            module_results = self._dispatch_agents(target, recon, agent_groups, session)

            # ── Phase 4: Enrichment ────────────────────────────────────────────
            # Suppress recon findings in single mode — analyst requested one
            # specific test; recon noise is irrelevant.
            _set("enrichment")
            recon_result = session["raw_results"]["recon"]
            if scan_mode == "single":
                recon_result = {**recon_result, "findings": []}
            all_results = [recon_result] + module_results
            session["enriched_findings"] = enrich_findings(all_results)

            # ── Phase 5: AI False Positive Analysis ────────────────────────────
            _set("ai_analysis")
            session["enriched_findings"] = analyse_findings(
                session["enriched_findings"]
            )

            # ── Phase 6: Reviewer Agent — build human review queue ─────────────
            _set("awaiting_validation")
            session["review_queue"] = _reviewer_agent.build_review_queue(
                session["enriched_findings"]
            )

            session["summary"] = self._build_summary(session["enriched_findings"], session)

        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Fatal error: {e}", exc_info=True)
            session["status"] = "error"
            session["error"]  = str(e)
        finally:
            end = datetime.utcnow()
            session["end_time"]         = end.isoformat()
            session["duration_seconds"] = round((end - start).total_seconds(), 2)
            if db:
                try:
                    crud.finalise_session(db, session)
                    if session.get("enriched_findings"):
                        crud.save_findings(db, session_id, session["enriched_findings"])
                except Exception as e:
                    logger.warning(f"[DB] Finalise session failed: {e}")

        return session

    # ── Agent selection ────────────────────────────────────────────────────────

    def _select_agents(self, domain: str, scan_mode: str,
                       requested_tests: list) -> dict:
        """
        Return {agent_name: hint_list} based on domain and scan mode.
        Agents receive hints as focus context — they still self-direct.
        Replaces KnowledgeAgent.resolve() + ExecutionPlan entirely.
        """
        hints = requested_tests or []

        if scan_mode == "single":
            # Run exactly one agent — the most relevant for the domain
            if domain == "cloud":
                return {"cloud_agent": hints}
            if domain == "network":
                return {"network_agent": hints}
            return {"web_agent": hints}

        # full / owasp / checklist — run all applicable agents
        agents = {}
        if domain == "cloud":
            agents["cloud_agent"] = hints
            # Cloud targets may also have a web interface
            agents["web_agent"]   = hints
        elif domain == "network":
            agents["network_agent"] = hints
        else:
            # web or unknown — run both web and network
            agents["web_agent"]     = hints
            agents["network_agent"] = hints

        # Cloud always opt-in via config flag regardless of domain
        _run_cloud = bool(self.config and getattr(self.config, "run_cloud", False))
        if _run_cloud and "cloud_agent" not in agents:
            agents["cloud_agent"] = hints

        return agents

    # ── Agent dispatch ─────────────────────────────────────────────────────────

    def _dispatch_agents(self, target: str, recon: dict,
                         agent_groups: dict, session: dict) -> list:
        results = []
        futures = {}

        task_map = {}
        if "web_agent" in agent_groups:
            _items = agent_groups["web_agent"]
            task_map["web_agent"] = lambda i=_items: _web_agent.run(
                target, self.config, checklist_items=i
            )
        if "network_agent" in agent_groups:
            _items = agent_groups["network_agent"]
            task_map["network_agent"] = lambda i=_items: _network_agent.run(
                target, recon, self.config, checklist_items=i
            )
        if "cloud_agent" in agent_groups:
            _items = agent_groups["cloud_agent"]
            task_map["cloud_agent"] = lambda i=_items: _cloud_agent.run(
                target, self.config, checklist_items=i
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            for agent_name, task in task_map.items():
                future = ex.submit(task)
                futures[future] = agent_name
                logger.info(f"[ORCHESTRATOR] Dispatched: {agent_name}")

            for future in concurrent.futures.as_completed(futures):
                agent_name = futures[future]
                try:
                    _timeout = 1000 if agent_name == "cloud_agent" else 300
                    result = future.result(timeout=_timeout)
                    session["raw_results"][agent_name] = result
                    session["agents_executed"].append(agent_name)
                    results.append(result)
                    logger.info(f"[ORCHESTRATOR] {agent_name} completed — "
                                f"{len(result.get('findings', []))} findings | "
                                f"tool: {result.get('tool_used', '?')}")
                except concurrent.futures.TimeoutError:
                    logger.error(f"[ORCHESTRATOR] {agent_name} timed out")
                except Exception as e:
                    logger.error(f"[ORCHESTRATOR] {agent_name} failed: {e}",
                                 exc_info=True)

        return results

    # ── Domain inference ───────────────────────────────────────────────────────

    def _infer_domain(self, target: str, recon: dict) -> str:
        host_type  = recon.get("host_type", "unknown")
        open_ports = {p["port"] for p in recon.get("open_ports", [])}
        t          = target.lower()

        CLOUD_KW  = ["aws", "amazon", "azure", "gcp", "google",
                     "cloudfront", "s3.", "blob.core"]
        WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

        if any(kw in t for kw in CLOUD_KW):
            return "cloud"
        if host_type == "web_application" or open_ports & WEB_PORTS:
            return "web"
        return "network"

    # ── Summary ────────────────────────────────────────────────────────────────

    def _build_summary(self, enriched: list, session: dict) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in enriched:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        score = (counts["Critical"] * 10 + counts["High"] * 7 +
                 counts["Medium"]  *  4 + counts["Low"]  * 1)

        tools = {}
        for f in enriched:
            t = f.get("tool_used", "unknown")
            tools[t] = tools.get(t, 0) + 1

        return {
            "total_findings":     len(enriched),
            "severity_breakdown": counts,
            "overall_risk_score": score,
            "risk_rating":        self._rating(score),
            "agents_run":         session["agents_executed"],
            "tool_breakdown":     tools,
            "scan_mode":          session["scan_mode"],
            "domain":             session["execution_plan"].get("domain", "unknown"),
            "scan_duration":      session.get("duration_seconds"),
        }

    @staticmethod
    def _rating(score: int) -> str:
        if score >= 50: return "CRITICAL"
        if score >= 25: return "HIGH"
        if score >= 10: return "MEDIUM"
        if score > 0:   return "LOW"
        return "CLEAN"
