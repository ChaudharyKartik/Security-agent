"""
Orchestrator Agent — Brain of the system.
Parallel Web / Network / Cloud execution via ThreadPoolExecutor.
ScanConfig flows through to every agent module.
Smarter target classification for IP / web / cloud routing.
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

WEB_PORTS      = {80, 443, 8080, 8443, 8000, 8888}
CLOUD_KEYWORDS = ["aws","amazon","azure","gcp","google","cloudfront",
                  "s3.","blob.core","appspot","lambda","elasticbeanstalk"]
DB_PORTS       = {3306, 5432, 6379, 9200, 27017, 1521, 1433}


class Orchestrator:
    def __init__(self, config=None):
        self.config = config

    def run(self, target: str, session_id: str, status_callback=None) -> dict:
        start = datetime.utcnow()
        logger.info(f"[ORCHESTRATOR] Session {session_id} — target: {target} — "
                    f"auth: {self.config.build_auth_summary() if self.config else 'none'}")

        session = {
            "session_id": session_id, "target": target,
            "start_time": start.isoformat(), "end_time": None,
            "duration_seconds": None, "modules_executed": [],
            "raw_results": {}, "enriched_findings": [],
            "summary": {}, "status": "running", "error": None,
            "auth_used": self.config.build_auth_summary() if self.config else "Unauthenticated",
        }

        def _set(s):
            session["status"] = s
            if status_callback: status_callback(session_id, s)

        try:
            # Phase 1: Recon
            _set("recon")
            recon = run_recon(target, self.config)
            session["raw_results"]["recon"] = recon
            session["modules_executed"].append("recon")

            # Phase 2: Decide
            modules = self._decide_modules(target, recon)
            logger.info(f"[ORCHESTRATOR] Modules: {modules}")

            # Phase 3: Parallel
            _set("scanning")
            module_results = self._run_parallel(target, recon, modules, session)

            # Phase 4: Enrich
            _set("enrichment")
            session["enriched_findings"] = enrich_findings(module_results)
            session["summary"]           = self._build_summary(session["enriched_findings"], session)
            _set("awaiting_validation")

        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Fatal: {e}", exc_info=True)
            session["status"] = "error"
            session["error"]  = str(e)
        finally:
            end = datetime.utcnow()
            session["end_time"]         = end.isoformat()
            session["duration_seconds"] = round((end - start).total_seconds(), 2)

        return session

    def _run_parallel(self, target, recon, modules, session) -> list:
        task_map = {
            "network": lambda: run_network_scan(target, recon, self.config),
            "web":     lambda: run_web_scan(target, self.config),
            "cloud":   lambda: run_cloud_scan(target, self.config),
        }
        results, futures = [], {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            for mod in modules:
                if mod in task_map:
                    futures[ex.submit(task_map[mod])] = mod

            for future in concurrent.futures.as_completed(futures):
                mod = futures[future]
                try:
                    result = future.result(timeout=300)
                    session["raw_results"][mod]    = result
                    session["modules_executed"].append(mod)
                    results.append(result)
                    logger.info(f"[ORCHESTRATOR] {mod} done — "
                                f"{len(result.get('findings',[]))} findings | "
                                f"tool: {result.get('tool_used','?')}")
                except concurrent.futures.TimeoutError:
                    logger.error(f"[ORCHESTRATOR] {mod} timed out")
                except Exception as e:
                    logger.error(f"[ORCHESTRATOR] {mod} failed: {e}", exc_info=True)
        return results

    def _decide_modules(self, target: str, recon: dict) -> list:
        modules    = ["network"]
        host_type  = recon.get("host_type","unknown")
        open_ports = {p["port"] for p in recon.get("open_ports",[])}
        t          = target.lower()

        # Web module
        if host_type == "web_application" or open_ports & WEB_PORTS:
            modules.append("web")

        # Cloud module
        if any(kw in t for kw in CLOUD_KEYWORDS):
            modules.append("cloud")
        elif self.config and self.config.run_cloud:
            modules.append("cloud")

        # If only DB ports open and no web → skip web module, keep network focus
        if not (open_ports & WEB_PORTS) and (open_ports & DB_PORTS) and "web" in modules:
            modules.remove("web")

        return list(dict.fromkeys(modules))  # preserve order, no dupes

    def _build_summary(self, enriched: list, session: dict) -> dict:
        counts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        for f in enriched:
            counts[f.get("severity","Info")] = counts.get(f.get("severity","Info"),0) + 1

        score = counts["Critical"]*10 + counts["High"]*7 + counts["Medium"]*4 + counts["Low"]*1

        # Tool breakdown
        tools = {}
        for f in enriched:
            t = f.get("tool_used","unknown")
            tools[t] = tools.get(t,0) + 1

        return {
            "total_findings":     len(enriched),
            "severity_breakdown": counts,
            "overall_risk_score": score,
            "risk_rating":        self._rating(score),
            "modules_run":        session["modules_executed"],
            "tool_breakdown":     tools,
            "scan_duration":      session.get("duration_seconds"),
        }

    @staticmethod
    def _rating(score: int) -> str:
        if score >= 50: return "CRITICAL"
        if score >= 25: return "HIGH"
        if score >= 10: return "MEDIUM"
        if score > 0:   return "LOW"
        return "CLEAN"
