"""
Web Agent — ZAP + Nuclei (concurrent) + WSTG-aligned HTTP probes.
Auth credentials from ScanConfig are injected into all requests.
Every finding captures request/response pairs and curl PoC commands.
Tool label: OWASP ZAP 2.14 + Nuclei v3 | Built-in HTTP Probe
"""
import concurrent.futures
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

import httpx

from modules.probes import run_probes

logger = logging.getLogger(__name__)

TOOL_ZAP      = "OWASP ZAP 2.14"
TOOL_NUCLEI   = "Nuclei v3"
TOOL_PROBE    = "Built-in HTTP Probe"

# Maps WSTG checklist IDs to Nuclei tag(s) for focused single/checklist scans.
# When checklist_ids is provided, only templates matching these tags run —
# reduces scan time from 10 min to under 60 s in single-vuln mode.
WSTG_TO_NUCLEI_TAGS: dict[str, str] = {
    "WSTG-INPV-01": "xss",
    "WSTG-INPV-02": "xss",
    "WSTG-INPV-05": "sqli",
    "WSTG-INPV-06": "ldap",
    "WSTG-INPV-07": "xxe",
    "WSTG-INPV-08": "ssti",
    "WSTG-INPV-12": "rce",
    "WSTG-INPV-13": "ssrf",
    "WSTG-INPV-18": "ssti",
    "WSTG-CONF-04": "exposure",
    "WSTG-CONF-05": "exposure",
    "WSTG-CONF-07": "misconfiguration",
    "WSTG-ATHZ-01": "lfi",
    "WSTG-ATHZ-04": "idor",
    "WSTG-ATHN-02": "default-login",
    "WSTG-CLNT-07": "cors",
    "WSTG-INFO-04": "graphql",
    "WSTG-CRYP-01": "ssl",
    "WSTG-BUSL-08": "fileupload",
}




def run_web_scan(target: str, config=None, checklist_items=None) -> dict:
    logger.info(f"[WEB] Starting web scan: {target}")
    start     = datetime.utcnow()
    url       = target if target.startswith("http") else f"http://{target}"
    auth_hdrs = config.build_auth_headers() if config else {}
    zap_base  = (config.zap_api_base if config else None) or "http://localhost:8090"
    zap_key   = (config.zap_api_key  if config else None) or "changeme"

    # Extract WSTG IDs from execution plan to drive probe selection.
    # None = full scan (all probes run); a list limits to registered IDs only.
    checklist_ids = None
    if checklist_items:
        checklist_ids = [
            item.checklist_id for item in checklist_items
            if hasattr(item, "checklist_id")
        ]

    # Derive Nuclei tags from the checklist IDs so focused scans (single /
    # checklist mode) only run relevant templates instead of the full library.
    # This cuts Nuclei scan time from ~10 min to under 60 s for single-vuln scans.
    nuclei_tags = None
    if checklist_ids:
        tags = {WSTG_TO_NUCLEI_TAGS[wid] for wid in checklist_ids if wid in WSTG_TO_NUCLEI_TAGS}
        if tags:
            nuclei_tags = ",".join(sorted(tags))
            logger.info(f"[WEB] Nuclei tag filter: {nuclei_tags}")

    base_hdrs = {"User-Agent": "Mozilla/5.0 SecurityProbe/1.0"}
    base_hdrs.update(auth_hdrs)

    # ZAP, Nuclei, and probes run concurrently.
    # Probes always run regardless of ZAP/Nuclei outcome.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        zap_future    = ex.submit(_try_zap_scan, url, zap_base, zap_key, config)
        nuclei_future = ex.submit(_try_nuclei_scan, url, config, nuclei_tags)
        probe_future  = ex.submit(run_probes, url, base_hdrs, config, checklist_ids)
        zap_result    = zap_future.result()
        nuclei_result = nuclei_future.result()
        probe_result  = probe_future.result() or []

    findings: list = []
    tools:    list = []

    if zap_result is not None:
        findings.extend(zap_result)
        tools.append(TOOL_ZAP)
        logger.info(f"[WEB] ZAP: {len(zap_result)} alerts")
    else:
        logger.warning("[WEB] ZAP unavailable or failed — no ZAP results")

    if nuclei_result is not None:
        findings.extend(nuclei_result)
        tools.append(TOOL_NUCLEI)
        logger.info(f"[WEB] Nuclei: {len(nuclei_result)} findings")
    else:
        logger.info("[WEB] Nuclei unavailable or no findings")

    # Always merge probe findings; dedup removes overlaps with ZAP/Nuclei
    findings.extend(probe_result)
    logger.info(f"[WEB] Probes: {len(probe_result)} findings")

    if not tools:
        tools = [TOOL_PROBE]

    before   = len(findings)
    findings = _dedup_findings(findings)
    logger.info(f"[WEB] Final: {before} raw → {len(findings)} after dedup | tools: {tools}")

    return {
        "module":    "web",
        "target":    target,
        "tool_used": " + ".join(tools),
        "scan_time": (datetime.utcnow() - start).total_seconds(),
        "findings":  findings,
        "auth_used": config.build_auth_summary() if config else "Unauthenticated",
    }


# ── ZAP ───────────────────────────────────────────────────────────────────────

def _try_zap_scan(url: str, base: str, key: str, config) -> list | None:
    try:
        r = httpx.get(f"{base}/JSON/core/view/version/", params={"apikey": key}, timeout=4)
        if r.status_code != 200:
            return None

        # Clear previous scan state so stale alerts don't contaminate this run
        try:
            httpx.get(f"{base}/JSON/core/action/newSession/",
                      params={"apikey": key, "overwrite": "true"}, timeout=10)
        except Exception:
            pass

        # Set up context + auth if credentials provided
        if config and config.auth_type != "none":
            _configure_zap_auth(base, key, url, config)

        # Tune depth based on scan_depth config
        depth = getattr(config, "scan_depth", "standard") if config else "standard"
        _DEPTH_CFG = {
            "quick":    {"max_children": 10,  "spider_timeout": 120, "ascan_timeout": 120},
            "standard": {"max_children": 50,  "spider_timeout": 180, "ascan_timeout": 300},
            "deep":     {"max_children": 200, "spider_timeout": 300, "ascan_timeout": 600},
        }
        dcfg = _DEPTH_CFG.get(depth, _DEPTH_CFG["standard"])

        # Capture the scan ID from spider/ascan action responses.
        # ZAP status endpoints expect a scanId integer, not a URL string.
        spider_r = httpx.get(f"{base}/JSON/spider/action/scan/",
                             params={"apikey": key, "url": url,
                                     "maxChildren": dcfg["max_children"]}, timeout=10)
        spider_id = spider_r.json().get("scan", "0")
        logger.info(f"[ZAP] Spider started — id={spider_id} depth={depth}")
        _zap_wait("spider", base, key, scan_id=spider_id, timeout=dcfg["spider_timeout"])

        try:
            urls_r   = httpx.get(f"{base}/JSON/spider/view/results/",
                                 params={"apikey": key, "scanId": spider_id}, timeout=5)
            url_count = len(urls_r.json().get("results", []))
            logger.info(f"[ZAP] Spider done — {url_count} URLs found")
        except Exception:
            logger.info("[ZAP] Spider done — URL count unavailable")

        ascan_r = httpx.get(f"{base}/JSON/ascan/action/scan/",
                            params={"apikey": key, "url": url, "recurse": "true"}, timeout=10)
        ascan_id = ascan_r.json().get("scan", "0")
        logger.info(f"[ZAP] Active scan started — id={ascan_id}")
        _zap_wait("ascan", base, key, scan_id=ascan_id, timeout=dcfg["ascan_timeout"])
        logger.info("[ZAP] Active scan done")

        # Fetch all alerts then filter by target host in Python.
        # Avoids trailing-slash / redirect mismatches with the ZAP baseurl param.
        alerts_r = httpx.get(f"{base}/JSON/core/view/alerts/",
                             params={"apikey": key, "start": "0", "count": "5000"}, timeout=15)
        all_alerts  = alerts_r.json().get("alerts", [])
        parsed_host = urlparse(url).netloc
        alerts = [a for a in all_alerts if parsed_host in a.get("url", "")]
        logger.info(f"[ZAP] Alerts: {len(all_alerts)} total, {len(alerts)} for {parsed_host}")

        # Fetch real HTTP request/response for High/Medium alerts in parallel.
        # Low/Info findings keep raw ZAP fields — fetching all messages for
        # informational alerts adds latency without meaningful PoC value.
        def enrich(alert: dict) -> dict:
            message = None
            msg_id  = alert.get("messageId", "")
            if msg_id and alert.get("risk", "") in ("High", "Critical", "Medium"):
                message = _fetch_zap_message(base, key, msg_id)
            return _zap_to_finding(alert, message)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(enrich, alerts))

        # Clean up replacer rules added for this scan so they don't persist
        # across future ZAP scans on the same instance.
        if config and config.auth_type in ("token", "cookie", "apikey"):
            try:
                rules_r = httpx.get(f"{base}/JSON/replacer/view/rules/",
                                    params={"apikey": key}, timeout=5)
                for rule in rules_r.json().get("rules", []):
                    if rule.get("description") == "auth_inject":
                        httpx.get(f"{base}/JSON/replacer/action/removeRule/",
                                  params={"apikey": key,
                                          "description": "auth_inject"}, timeout=5)
            except Exception:
                pass

        return results
    except Exception as e:
        logger.warning(f"[ZAP] Scan failed: {e}", exc_info=True)
        return None


def _configure_zap_auth(base: str, key: str, url: str, config):
    """
    Push auth credentials into ZAP so every spider/active-scan request
    is authenticated.

    Strategy per auth type:
      token / cookie / apikey  — ZAP Replacer rules inject the header on
                                  every request (no context needed)
      basic                    — ZAP httpAuthentication context + user
      form                     — ZAP formBasedAuthentication context + user
    """
    try:
        parsed = urlparse(url)

        # ── Header-based auth (token / cookie / apikey) ───────────────────
        # Use ZAP Replacer to inject the header into every outgoing request.
        # This works regardless of scan type and requires no ZAP context.
        header_to_inject: dict | None = None

        if config.auth_type == "token" and config.auth_token:
            value = f"{config.token_prefix} {config.auth_token}".strip()
            header_to_inject = {"header": config.token_header or "Authorization",
                                 "value": value}

        elif config.auth_type == "cookie" and config.session_cookie_value:
            name  = config.session_cookie_name or "session"
            header_to_inject = {"header": "Cookie",
                                 "value": f"{name}={config.session_cookie_value}"}

        elif config.auth_type == "apikey" and config.api_key_value:
            if config.api_key_in in ("header", None):
                header_to_inject = {"header": config.api_key_name or "X-API-Key",
                                     "value": config.api_key_value}
            elif config.api_key_in == "query":
                # Replacer can't modify query params — fall through; the
                # probes path still sends it via build_auth_headers()
                logger.info("[ZAP-AUTH] api_key_in=query: injected via probes only")

        if header_to_inject:
            httpx.get(
                f"{base}/JSON/replacer/action/addRule/",
                params={
                    "apikey":       key,
                    "description":  "auth_inject",
                    "enabled":      "true",
                    "matchType":    "REQ_HEADER",
                    "matchRegex":   "false",
                    "matchString":  header_to_inject["header"],
                    "replacement":  header_to_inject["value"],
                    "initiators":   "",
                },
                timeout=5,
            )
            logger.info(f"[ZAP-AUTH] Replacer rule added for header: {header_to_inject['header']}")
            return  # no context needed for header injection

        # ── Context-based auth (basic / form) ─────────────────────────────
        ctx_r  = httpx.get(f"{base}/JSON/context/action/newContext/",
                           params={"apikey": key, "contextName": "authed"}, timeout=5)
        ctx_id = ctx_r.json().get("contextId", "1")

        # Include target URL in context scope
        httpx.get(f"{base}/JSON/context/action/includeInContext/",
                  params={"apikey": key, "contextId": ctx_id,
                          "regex": f"{parsed.scheme}://{parsed.netloc}.*"}, timeout=5)

        if config.auth_type == "basic" and config.username and config.password:
            # Set HTTP authentication method
            httpx.get(f"{base}/JSON/authentication/action/setAuthenticationMethod/",
                      params={"apikey": key, "contextId": ctx_id,
                              "authMethodName": "httpAuthentication",
                              "authMethodConfigParams":
                                  f"hostname={parsed.hostname}&realm="}, timeout=5)
            # Create user with credentials
            user_r = httpx.get(f"{base}/JSON/users/action/newUser/",
                                params={"apikey": key, "contextId": ctx_id,
                                        "name": "scan_user"}, timeout=5)
            user_id = user_r.json().get("userId", "0")
            import urllib.parse as _up
            creds = _up.urlencode({"username": config.username,
                                   "password": config.password})
            httpx.get(f"{base}/JSON/users/action/setAuthenticationCredentials/",
                      params={"apikey": key, "contextId": ctx_id,
                              "userId": user_id,
                              "authCredentialsConfigParams": creds}, timeout=5)
            httpx.get(f"{base}/JSON/users/action/setUserEnabled/",
                      params={"apikey": key, "contextId": ctx_id,
                              "userId": user_id, "enabled": "true"}, timeout=5)
            httpx.get(f"{base}/JSON/forcedUser/action/setForcedUser/",
                      params={"apikey": key, "contextId": ctx_id,
                              "userId": user_id}, timeout=5)
            httpx.get(f"{base}/JSON/forcedUser/action/setForcedUserModeEnabled/",
                      params={"apikey": key, "enabled": "true"}, timeout=5)
            logger.info(f"[ZAP-AUTH] Basic auth configured for user: {config.username}")

        elif config.auth_type == "form" and config.login_url and config.username:
            username_field = config.username_field or "username"
            password_field = config.password_field or "password"
            import urllib.parse as _up
            login_data = _up.urlencode({
                username_field: config.username,
                password_field: config.password or "",
            })
            method_params = _up.urlencode({
                "loginUrl":         config.login_url,
                "loginRequestData": login_data,
            })
            httpx.get(f"{base}/JSON/authentication/action/setAuthenticationMethod/",
                      params={"apikey": key, "contextId": ctx_id,
                              "authMethodName": "formBasedAuthentication",
                              "authMethodConfigParams": method_params}, timeout=5)
            # Create user
            user_r = httpx.get(f"{base}/JSON/users/action/newUser/",
                                params={"apikey": key, "contextId": ctx_id,
                                        "name": "scan_user"}, timeout=5)
            user_id = user_r.json().get("userId", "0")
            creds = _up.urlencode({"username": config.username,
                                   "password": config.password or ""})
            httpx.get(f"{base}/JSON/users/action/setAuthenticationCredentials/",
                      params={"apikey": key, "contextId": ctx_id,
                              "userId": user_id,
                              "authCredentialsConfigParams": creds}, timeout=5)
            httpx.get(f"{base}/JSON/users/action/setUserEnabled/",
                      params={"apikey": key, "contextId": ctx_id,
                              "userId": user_id, "enabled": "true"}, timeout=5)
            httpx.get(f"{base}/JSON/forcedUser/action/setForcedUser/",
                      params={"apikey": key, "contextId": ctx_id,
                              "userId": user_id}, timeout=5)
            httpx.get(f"{base}/JSON/forcedUser/action/setForcedUserModeEnabled/",
                      params={"apikey": key, "enabled": "true"}, timeout=5)
            logger.info(f"[ZAP-AUTH] Form auth configured — login: {config.login_url}")

    except Exception as e:
        logger.warning(f"[WEB] ZAP auth config failed: {e}")


def _zap_wait(task: str, base: str, key: str, scan_id: str = "0", timeout: int = 180):
    # Poll ZAP status by scanId. The ZAP API's status endpoint returns
    # percentage complete (0-100) for a given scan ID.
    # spider/view/status and ascan/view/status endpoints return progress for a
    # specific scan identified by its integer scan ID, not the target URL.
    ep = {"spider": f"{base}/JSON/spider/view/status/",
          "ascan":  f"{base}/JSON/ascan/view/status/"}
    for _ in range(timeout // 3):
        try:
            r = httpx.get(ep[task], params={"apikey": key, "scanId": scan_id}, timeout=5)
            if int(r.json().get("status", 0)) >= 100:
                return
        except Exception:
            return
        time.sleep(3)


def _fetch_zap_message(base: str, key: str, message_id: str) -> dict | None:
    """Fetch raw HTTP request/response + HAR for a ZAP message ID."""
    try:
        r = httpx.get(f"{base}/JSON/core/view/message/",
                      params={"apikey": key, "id": message_id}, timeout=5)
        if r.status_code != 200:
            return None
        msg = r.json().get("message", {})
        # Also fetch HAR — gives a Burp-importable format for replay
        try:
            har_r = httpx.get(f"{base}/JSON/core/view/messageHar/",
                               params={"apikey": key, "id": message_id}, timeout=5)
            if har_r.status_code == 200:
                msg["_har"] = har_r.json().get("har", {})
            else:
                logger.debug(f"[ZAP] HAR not available for message {message_id} (HTTP {har_r.status_code})")
        except Exception:
            pass
        return msg
    except Exception:
        pass
    return None



def _zap_to_finding(alert: dict, message: dict | None = None) -> dict:
    risk_map = {"High":"High","Medium":"Medium","Low":"Low","Informational":"Info","":"Info"}
    url = alert.get("url", "")

    evidence: dict = {
        "type":     "zap_alert",
        "evidence": alert.get("evidence", ""),
        "attack":   alert.get("attack",   ""),
        "param":    alert.get("param",    ""),
    }

    if message:
        req_hdr  = message.get("requestHeader",  "")
        req_body = message.get("requestBody",    "")
        resp_hdr = message.get("responseHeader", "")
        resp_body= message.get("responseBody",   "")

        # Combine request header + body into one block for display
        full_request = req_hdr[:1500]
        if req_body:
            full_request = full_request.rstrip() + "\r\n\r\n" + req_body[:500]

        evidence["request_header"]   = req_hdr[:1500]
        evidence["request_body"]     = req_body[:500]
        evidence["request"]          = full_request
        evidence["response_header"]  = resp_hdr[:500]
        evidence["response_snippet"] = resp_body[:800]
        if message.get("_har"):
            evidence["har"] = message["_har"]
    else:
        # Low/Info — store raw ZAP fields; no curl reconstruction
        evidence["poc_url"]    = url
        evidence["poc_param"]  = alert.get("param",  "")
        evidence["poc_attack"] = alert.get("attack", "")

    return {
        "name":        alert.get("name",        "ZAP Alert"),
        "type":        "web_vulnerability",
        "risk":        risk_map.get(alert.get("risk", ""), "Info"),
        "url":         url,
        "description": alert.get("description", ""),
        "solution":    alert.get("solution",    ""),
        "confidence":  alert.get("confidence",  ""),
        "cwe":         alert.get("cweid",       ""),
        "evidence":    evidence,
    }


# ── Deduplication ────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

def _dedup_findings(findings: list) -> list:
    """
    Merge findings from multiple tools that describe the same vulnerability.
    Key: (url, normalised name). On collision the higher-severity finding
    survives and both evidence dicts are merged — so ZAP's request/response
    and Nuclei's template/CVE metadata end up in one record.
    """
    seen:   dict = {}   # key → index in `out`
    out:    list = []

    for f in findings:
        raw_url  = f.get("url", "")
        try:
            host = urlparse(raw_url).netloc or raw_url
        except Exception:
            host = raw_url
        key = (host, f.get("name", "").lower().strip(), f.get("param", ""))
        if key not in seen:
            seen[key] = len(out)
            out.append(f)
        else:
            existing = out[seen[key]]

            # Keep the higher severity
            if (_SEVERITY_ORDER.get(f.get("risk", "Info"), 0) >
                    _SEVERITY_ORDER.get(existing.get("risk", "Info"), 0)):
                existing["risk"] = f["risk"]

            # Merge evidence — existing keys are not overwritten so the richer
            # source (usually ZAP with full req/resp) keeps priority; the other
            # source fills in any gaps (e.g. Nuclei's template_id / cve fields).
            merged_ev = dict(f.get("evidence", {}))
            merged_ev.update(existing.get("evidence", {}))
            existing["evidence"] = merged_ev

            # Carry over CVE / CWE if the survivor is missing them
            for field in ("cve", "cwe", "confidence"):
                if field not in existing and field in f:
                    existing[field] = f[field]

            # Note that both tools flagged this finding
            sources = existing.get("_sources", [existing.get("source", "zap")])
            if f.get("source") and f["source"] not in sources:
                sources.append(f["source"])
            existing["_sources"] = sources

    return out


# ── Nuclei ────────────────────────────────────────────────────────────────────

def _try_nuclei_scan(url: str, config, tags: str | None = None) -> list | None:
    """
    Run Nuclei CLI against target. Returns findings list or None if unavailable.
    Auth headers are injected via -H flags; depth controls severity filter + rate.
    tags: comma-separated Nuclei tag filter (e.g. "sqli") — None runs all templates.
    """
    if not shutil.which("nuclei"):
        logger.info("[NUCLEI] nuclei not found in PATH — skipping")
        return None

    depth = getattr(config, "scan_depth", "standard") if config else "standard"
    _DEPTH_CFG = {
        "quick":    {"severity": "critical,high,medium",             "rate": 50,  "timeout": 120},
        "standard": {"severity": "critical,high,medium,low",         "rate": 150, "timeout": 300},
        "deep":     {"severity": "critical,high,medium,low,info",    "rate": 300, "timeout": 600},
    }
    dcfg = _DEPTH_CFG.get(depth, _DEPTH_CFG["standard"])

    # Tag-filtered scans are narrow by design — cap timeout at 60 s so a
    # focused single-vuln scan never blocks the pipeline for minutes.
    if tags:
        dcfg = {**dcfg, "timeout": min(dcfg["timeout"], 60)}

    auth_hdrs = config.build_auth_headers() if config else {}

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
        out_file = f.name

    try:
        cmd = [
            "nuclei", "-u", url,
            "-severity", dcfg["severity"],
            "-rate-limit", str(dcfg["rate"]),
            "-json-export", out_file,
            "-no-interactsh",
            "-silent",
            "-timeout", "10",
        ]
        if tags:
            cmd.extend(["-tags", tags])
        for hdr, val in auth_hdrs.items():
            cmd.extend(["-H", f"{hdr}: {val}"])

        logger.info(f"[NUCLEI] Scanning {url} (depth={depth}, severity={dcfg['severity']}"
                    + (f", tags={tags})" if tags else ")"))
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=dcfg["timeout"]
        )
        if proc.returncode not in (0, 1):
            logger.warning(f"[NUCLEI] Exited with code {proc.returncode}: {proc.stderr[:200]}")

        findings: list = []
        if os.path.exists(out_file):
            with open(out_file, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data    = json.loads(line)
                        finding = _nuclei_to_finding(data, url)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        pass

        logger.info(f"[NUCLEI] {len(findings)} findings")
        return findings

    except subprocess.TimeoutExpired:
        logger.warning(f"[NUCLEI] Scan timed out after {dcfg['timeout']}s")
        return []
    except Exception as e:
        logger.warning(f"[NUCLEI] Error: {e}")
        return None
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass


def _nuclei_to_finding(result: dict, target: str) -> dict | None:
    info = result.get("info", {})
    name = info.get("name") or result.get("template-id", "Nuclei Finding")

    severity  = info.get("severity", "info").capitalize()
    sev_map   = {"Critical": "Critical", "High": "High", "Medium": "Medium",
                 "Low": "Low", "Info": "Info"}
    risk      = sev_map.get(severity, "Info")

    tags  = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    ftype = _nuclei_type_from_tags(tags)

    url   = result.get("matched-at") or target
    desc  = info.get("description", "").strip() or \
            f"Nuclei template '{result.get('template-id', '')}' matched on target."
    sol   = (info.get("remediation", "") or
             f"Review and remediate '{name}' finding at {url}.").strip()

    evidence: dict = {
        "type":        "nuclei_finding",
        "template_id": result.get("template-id", ""),
        "matched_at":  url,
        "tags":        tags,
        "curl_poc":    f'curl -sk -i "{url}"',
    }
    req = result.get("request", "")
    resp = result.get("response", "")
    if req:
        evidence["request"] = req[:1500]
    if resp:
        evidence["response_snippet"] = resp[:800]

    # Extract CVE from classification block
    cve_id = ""
    classification = info.get("classification", {})
    if isinstance(classification, dict):
        cve_list = classification.get("cve-id", [])
        if isinstance(cve_list, list) and cve_list:
            cve_id = cve_list[0]
        elif isinstance(cve_list, str):
            cve_id = cve_list

    finding: dict = {
        "name":        name,
        "type":        ftype,
        "risk":        risk,
        "url":         url,
        "description": desc,
        "solution":    sol,
        "source":      "nuclei",
        "evidence":    evidence,
    }
    if cve_id:
        finding["cve"] = cve_id
    return finding


def _nuclei_type_from_tags(tags: list) -> str:
    tag_set = {t.lower() for t in tags}
    if "cve" in tag_set:
        return "vulnerable_version"
    if tag_set & {"default-login", "default-credentials"}:
        return "auth_misconfiguration"
    if tag_set & {"exposure", "disclosure"}:
        return "information_disclosure"
    if tag_set & {"ssl", "tls"}:
        return "ssl_error"
    return "web_vulnerability"


