"""
Orchestrator Agent — Brain of the system.
Spawns Web, Network, and Cloud agents in PARALLEL using ThreadPoolExecutor.
Aggregates results, drives enrichment, manages session state.
"""
import logging
import concurrent.futures
from datetime import datetime

from modules.recon import run_recon
from modules.network_module import run_network_scan
from modules.web_module import run_web_scan
from modules.cloud_module import run_cloud_scan
from enrichment import enrich_findings

logger = logging.getLogger(__name__)

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
CLOUD_KEYWORDS = ["aws", "amazon", "azure", "gcp", "google", "cloudfront",
                  "s3.", "blob.core", "appspot", "lambda", "elasticbeanstalk"]


class Orchestrator:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.run_cloud = self.config.get("run_cloud", False)

    def run(self, target: str, session_id: str, status_callback=None) -> dict:
        start_time = datetime.utcnow()
        logger.info(f"[ORCHESTRATOR] Session {session_id} started for: {target}")

        session = {
            "session_id":        session_id,
            "target":            target,
            "start_time":        start_time.isoformat(),
            "end_time":          None,
            "duration_seconds":  None,
            "modules_executed":  [],
            "raw_results":       {},
            "enriched_findings": [],
            "summary":           {},
            "status":            "running",
            "error":             None,
        }

        def _update_status(s: str):
            session["status"] = s
            if status_callback:
                status_callback(session_id, s)
            logger.info(f"[ORCHESTRATOR] Status -> {s}")

        try:
            # ── Phase 1: Recon ────────────────────────────────────────────
            _update_status("recon")
            recon_result = run_recon(target)
            session["raw_results"]["recon"] = recon_result
            session["modules_executed"].append("recon")

            # ── Phase 2: Decide modules ───────────────────────────────────
            modules_to_run = self._decide_modules(target, recon_result)
            logger.info(f"[ORCHESTRATOR] Modules selected: {modules_to_run}")

            # ── Phase 3: Parallel agent execution ─────────────────────────
            _update_status("scanning")
            module_results = self._run_parallel(target, recon_result, modules_to_run, session)

            # ── Phase 4: Enrichment ───────────────────────────────────────
            _update_status("enrichment")
            session["enriched_findings"] = enrich_findings(module_results)

            # ── Phase 5: Summary ──────────────────────────────────────────
            session["summary"] = self._build_summary(session["enriched_findings"], session)
            _update_status("awaiting_validation")

        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Fatal error in session {session_id}: {e}", exc_info=True)
            session["status"] = "error"
            session["error"] = str(e)
        finally:
            end_time = datetime.utcnow()
            session["end_time"] = end_time.isoformat()
            session["duration_seconds"] = round((end_time - start_time).total_seconds(), 2)
            logger.info(f"[ORCHESTRATOR] Session {session_id} finished in {session['duration_seconds']}s")

        return session

    # ── Parallel execution ────────────────────────────────────────────────────

    def _run_parallel(self, target: str, recon_result: dict,
                      modules_to_run: list, session: dict) -> list:
        """Run selected scan modules in parallel threads."""
        task_map = {
            "network": lambda: run_network_scan(target, recon_result),
            "web":     lambda: run_web_scan(target),
            "cloud":   lambda: run_cloud_scan(target),
        }

        module_results = []
        futures = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for module in modules_to_run:
                if module in task_map:
                    future = executor.submit(task_map[module])
                    futures[future] = module
                    logger.info(f"[ORCHESTRATOR] Submitted: {module} agent")

            for future in concurrent.futures.as_completed(futures):
                module = futures[future]
                try:
                    result = future.result(timeout=300)
                    session["raw_results"][module] = result
                    session["modules_executed"].append(module)
                    module_results.append(result)
                    logger.info(f"[ORCHESTRATOR] {module} agent completed — "
                                f"{len(result.get('findings', []))} findings")
                except concurrent.futures.TimeoutError:
                    logger.error(f"[ORCHESTRATOR] {module} agent timed out after 300s")
                except Exception as e:
                    logger.error(f"[ORCHESTRATOR] {module} agent failed: {e}", exc_info=True)

        return module_results

    # ── Module selection logic ────────────────────────────────────────────────

    def _decide_modules(self, target: str, recon_data: dict) -> list:
        modules = ["network"]  # always run network

        host_type  = recon_data.get("host_type", "unknown")
        open_ports = {p["port"] for p in recon_data.get("open_ports", [])}

        if host_type == "web_application":
            modules.append("web")
        elif open_ports & WEB_PORTS:
            modules.append("web")

        if self.run_cloud or any(kw in target.lower() for kw in CLOUD_KEYWORDS):
            modules.append("cloud")

        return modules

    # ── Summary builder ───────────────────────────────────────────────────────

    def _build_summary(self, enriched: list, session: dict) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in enriched:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        # Weighted risk score
        score = (counts["Critical"] * 10 + counts["High"] * 7 +
                 counts["Medium"] * 4 + counts["Low"] * 1)

        return {
            "total_findings":      len(enriched),
            "severity_breakdown":  counts,
            "overall_risk_score":  score,
            "risk_rating":         self._score_to_rating(score),
            "modules_run":         session["modules_executed"],
            "scan_duration":       session.get("duration_seconds"),
        }

    @staticmethod
    def _score_to_rating(score: int) -> str:
        if score >= 50: return "CRITICAL"
        if score >= 25: return "HIGH"
        if score >= 10: return "MEDIUM"
        if score > 0:   return "LOW"
        return "CLEAN"
