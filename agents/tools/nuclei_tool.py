"""
nuclei_tool — Nuclei wrapper for LLM-driven agents.

Runs nuclei with JSON-lines output, parses results, and returns structured
findings the LLM can evaluate. Replaces the nuclei call in web_module.py.
"""
import json
import shutil
import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 300
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


def run_nuclei(
    target:    str,
    tags:      Optional[list] = None,
    templates: Optional[list] = None,
    severity:  Optional[str]  = None,
    timeout:   int            = _DEFAULT_TIMEOUT,
) -> dict:
    """Run a Nuclei scan against a target and return structured findings."""
    if not shutil.which("nuclei"):
        return {
            "error": "nuclei is not installed or not in PATH. "
                     "Install: https://github.com/projectdiscovery/nuclei"
        }

    cmd = ["nuclei", "-target", target, "-json", "-silent"]

    if tags:
        # Ollama sometimes passes tags as a string repr of a list e.g. "['cve','misconfig']"
        if isinstance(tags, str):
            import ast
            try:
                tags = ast.literal_eval(tags)
            except Exception:
                tags = [t.strip().strip("'\"") for t in tags.strip("[]").split(",") if t.strip()]
        if tags:
            cmd += ["-tags", ",".join(str(t) for t in tags)]
    if templates:
        cmd += ["-t", ",".join(templates)]
    if severity:
        sev = severity.lower()
        if sev not in _VALID_SEVERITIES:
            return {"error": f"Invalid severity filter '{severity}'. "
                             f"Valid: {_VALID_SEVERITIES}"}
        cmd += ["-severity", sev]

    logger.info(f"[NUCLEI] Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"nuclei timed out after {timeout}s", "target": target}
    except Exception as e:
        return {"error": f"nuclei execution failed: {e}", "target": target}

    if proc.returncode not in (0, 1):
        return {
            "error":  f"nuclei exited {proc.returncode}",
            "stderr": proc.stderr[:1000],
            "target": target,
        }

    findings = _parse_jsonl(proc.stdout)
    return {
        "target":        target,
        "total":         len(findings),
        "findings":      findings,
        "error":         None,
    }


def _parse_jsonl(output: str) -> list:
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        findings.append({
            "template_id": item.get("template-id", ""),
            "name":        info.get("name", ""),
            "severity":    info.get("severity", ""),
            "description": info.get("description", ""),
            "tags":        info.get("tags", []),
            "matched_at":  item.get("matched-at", ""),
            "host":        item.get("host", ""),
            "type":        item.get("type", ""),
            "matcher":     item.get("matcher-name", ""),
            "extracted":   item.get("extracted-results", []),
            "curl_command":item.get("curl-command", ""),
            "timestamp":   item.get("timestamp", ""),
            "references":  info.get("reference", []),
        })

    return findings


run_nuclei.__schema__ = {
    "name": "run_nuclei",
    "description": (
        "Run a Nuclei template scan against a target URL. Nuclei covers CVEs, "
        "misconfigurations, exposed panels, default credentials, and more. "
        "Use tags to focus (e.g. ['xss', 'sqli', 'cve']) or templates for specific checks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or host to scan.",
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by template tags (e.g. ['xss', 'sqli', 'lfi', 'cve', 'misconfig']).",
            },
            "templates": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific template paths or directories to run.",
            },
            "severity": {
                "type": "string",
                "enum": sorted(_VALID_SEVERITIES),
                "description": "Only run templates of this severity or above.",
            },
            "timeout": {
                "type": "integer",
                "description": "Scan timeout in seconds (default 300).",
                "default": _DEFAULT_TIMEOUT,
            },
        },
        "required": ["target"],
    },
}
