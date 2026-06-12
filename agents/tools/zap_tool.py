"""
zap_tool — OWASP ZAP wrapper for LLM-driven agents.

Connects to a running ZAP daemon via the REST API (zapv2 Python client).
Supports spider, passive scan, and active scan modes.
Replaces the ZAP orchestration in web_module.py.

ZAP must be running before this tool is called:
    zap.sh -daemon -port 8090 -config api.disablekey=true
"""
import time
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_ZAP_HOST    = os.environ.get("ZAP_HOST", "127.0.0.1")
_ZAP_PORT    = int(os.environ.get("ZAP_PORT", "8090"))
_ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")

_SPIDER_TIMEOUT      = 120   # seconds
_ACTIVE_SCAN_TIMEOUT = 600
_POLL_INTERVAL       = 5

_VALID_SCAN_TYPES = {"spider", "passive", "active"}


def run_zap(
    target:    str,
    scan_type: str           = "passive",
    context:   Optional[str] = None,
    **kwargs,
) -> dict:
    """Run a ZAP spider/passive/active scan and return structured alerts."""
    # Accept any scan-type alias Ollama might invent (scan, spider, mode, type, ...)
    for _key in ("scan", "spider", "mode", "type", "scan_mode"):
        if _key in kwargs:
            scan_type = kwargs[_key]
            break
    scan_type = scan_type.lower()
    if scan_type not in _VALID_SCAN_TYPES:
        return {
            "error": f"Invalid scan_type '{scan_type}'. "
                     f"Must be one of: {_VALID_SCAN_TYPES}"
        }

    try:
        from zapv2 import ZAPv2
    except ImportError:
        return {
            "error": "python-owasp-zap-v2.4 not installed. "
                     "Run: pip install python-owasp-zap-v2.4"
        }

    zap = ZAPv2(
        apikey=_ZAP_API_KEY,
        proxies={"http": f"http://{_ZAP_HOST}:{_ZAP_PORT}",
                 "https": f"http://{_ZAP_HOST}:{_ZAP_PORT}"},
    )

    try:
        zap.core.version
    except Exception:
        return {
            "error": f"Cannot connect to ZAP at {_ZAP_HOST}:{_ZAP_PORT}. "
                     "Ensure ZAP is running in daemon mode."
        }

    logger.info(f"[ZAP] Connected. scan_type={scan_type} target={target}")

    try:
        if scan_type in ("spider", "active"):
            spider_id = zap.spider.scan(target, apikey=_ZAP_API_KEY)
            _wait_for(
                poll_fn  = lambda: int(zap.spider.status(spider_id)),
                label    = "spider",
                target   = target,
                timeout  = _SPIDER_TIMEOUT,
            )

        if scan_type == "active":
            ascan_id = zap.ascan.scan(target, apikey=_ZAP_API_KEY)
            _wait_for(
                poll_fn  = lambda: int(zap.ascan.status(ascan_id)),
                label    = "active scan",
                target   = target,
                timeout  = _ACTIVE_SCAN_TIMEOUT,
            )

        raw_alerts = zap.core.alerts(baseurl=target)
        alerts = [_parse_alert(a) for a in raw_alerts]

        return {
            "target":    target,
            "scan_type": scan_type,
            "total":     len(alerts),
            "alerts":    alerts,
            "error":     None,
        }

    except _TimeoutError as e:
        return {"error": str(e), "target": target, "scan_type": scan_type}
    except Exception as e:
        logger.error(f"[ZAP] Unexpected error: {e}", exc_info=True)
        return {"error": f"ZAP scan failed: {e}", "target": target}


def _wait_for(poll_fn, label: str, target: str, timeout: int):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            progress = poll_fn()
        except Exception:
            progress = 0
        if progress >= 100:
            logger.info(f"[ZAP] {label} complete for {target}")
            return
        logger.debug(f"[ZAP] {label} progress: {progress}%")
        time.sleep(_POLL_INTERVAL)
    raise _TimeoutError(f"ZAP {label} timed out after {timeout}s for {target}")


class _TimeoutError(Exception):
    pass


def _parse_alert(alert: dict) -> dict:
    return {
        "alert_id":   alert.get("id", ""),
        "name":       alert.get("alert", ""),
        "risk":       alert.get("risk", ""),
        "confidence": alert.get("confidence", ""),
        "url":        alert.get("url", ""),
        "description":alert.get("description", "")[:500],
        "solution":   alert.get("solution", "")[:300],
        "evidence":   alert.get("evidence", ""),
        "cwe_id":     f"CWE-{alert.get('cweid', '')}" if alert.get("cweid") else "",
        "wasc_id":    alert.get("wascid", ""),
        "reference":  alert.get("reference", "")[:300],
    }


run_zap.__schema__ = {
    "name": "run_zap",
    "description": (
        "Run an OWASP ZAP scan against a web target. "
        "'spider' crawls the application to discover endpoints. "
        "'passive' inspects traffic observed during spidering without sending attack payloads. "
        "'active' runs full active attack tests (slowest, most thorough). "
        "Returns a list of ZAP alerts with risk level and evidence."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Base URL of the web application to scan.",
            },
            "scan_type": {
                "type": "string",
                "enum": sorted(_VALID_SCAN_TYPES),
                "description": "Scan mode: 'spider', 'passive', or 'active' (default: 'passive').",
                "default": "passive",
            },
        },
        "required": ["target"],
    },
}
