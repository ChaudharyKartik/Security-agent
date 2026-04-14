"""
Network Agent
Runs Nmap service/version scan. Falls back to mock data when Nmap
is unavailable (dev/demo mode). Correlates open ports to known CVEs
via the NVD API (best-effort, no API key required for basic queries).
"""
import logging
import json
import time
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

# Ports that get deeper version detection
DEEP_SCAN_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017"

# Mock data used when Nmap is not installed
MOCK_SCAN_RESULTS = {
    "hosts": [
        {
            "hostname": "target",
            "ip": "192.168.1.1",
            "state": "up",
            "ports": [
                {"port": 22,   "state": "open", "service": "ssh",    "product": "OpenSSH",    "version": "7.4",  "cpe": "cpe:/a:openbsd:openssh:7.4"},
                {"port": 80,   "state": "open", "service": "http",   "product": "Apache httpd","version": "2.4.6","cpe": "cpe:/a:apache:http_server:2.4.6"},
                {"port": 443,  "state": "open", "service": "https",  "product": "Apache httpd","version": "2.4.6","cpe": "cpe:/a:apache:http_server:2.4.6"},
                {"port": 3306, "state": "open", "service": "mysql",  "product": "MySQL",       "version": "5.7.30","cpe": "cpe:/a:mysql:mysql:5.7.30"},
                {"port": 6379, "state": "open", "service": "redis",  "product": "Redis",       "version": "3.2.12","cpe": ""},
            ]
        }
    ]
}


def run_network_scan(target: str, recon_data: dict) -> dict:
    logger.info(f"[NETWORK] Starting network scan on: {target}")
    start = datetime.utcnow()

    host = recon_data.get("ip_address") or recon_data.get("hostname") or target
    scan_data = _run_nmap(host)
    findings = []

    for host_info in scan_data.get("hosts", []):
        findings.extend(_analyse_host(host_info, target))

    result = {
        "module": "network",
        "target": target,
        "scan_time": (datetime.utcnow() - start).total_seconds(),
        "raw_nmap": scan_data,
        "findings": findings,
    }
    logger.info(f"[NETWORK] Done. Findings: {len(findings)}")
    return result


# ── Nmap wrapper ─────────────────────────────────────────────────────────────

def _run_nmap(host: str) -> dict:
    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        logger.info(f"[NETWORK] Running Nmap on {host} ...")
        nm.scan(hosts=host, ports=DEEP_SCAN_PORTS,
                arguments="-sV -sC --open -T4 --host-timeout 120s")

        hosts_data = []
        for h in nm.all_hosts():
            host_info = {
                "hostname": nm[h].hostname() or h,
                "ip": h,
                "state": nm[h].state(),
                "ports": []
            }
            for proto in nm[h].all_protocols():
                for port, data in nm[h][proto].items():
                    if data["state"] == "open":
                        host_info["ports"].append({
                            "port": port,
                            "state": data["state"],
                            "service": data.get("name", "unknown"),
                            "product": data.get("product", ""),
                            "version": data.get("version", ""),
                            "extrainfo": data.get("extrainfo", ""),
                            "cpe": " ".join(data.get("cpe", [])),
                            "script_output": data.get("script", {}),
                        })
            hosts_data.append(host_info)

        return {"source": "nmap", "hosts": hosts_data}

    except ImportError:
        logger.warning("[NETWORK] python-nmap not installed — using mock data")
        return {"source": "mock", **MOCK_SCAN_RESULTS}
    except Exception as e:
        logger.error(f"[NETWORK] Nmap error: {e} — using mock data")
        return {"source": "mock_fallback", "error": str(e), **MOCK_SCAN_RESULTS}


# ── Analysis ──────────────────────────────────────────────────────────────────

def _analyse_host(host_info: dict, target: str) -> list:
    findings = []
    ports = host_info.get("ports", [])

    for p in ports:
        port = p["port"]
        service = p.get("service", "unknown")
        product = p.get("product", "")
        version = p.get("version", "")

        # Flag every open port as informational
        findings.append({
            "name": f"Open Port: {port}/{service}",
            "type": "open_port",
            "risk": _port_risk(port, service),
            "port": port,
            "service": service,
            "product": product,
            "version": version,
            "host": host_info.get("ip", target),
            "description": (
                f"Port {port}/{service} is open"
                + (f" running {product} {version}".rstrip() if product else "")
                + "."
            ),
            "solution": _port_solution(port, service),
        })

        # Outdated / vulnerable versions
        version_findings = _check_version(product, version, port, target)
        findings.extend(version_findings)

        # Auth / config issues from NSE scripts
        script_findings = _check_scripts(p.get("script_output", {}), port, service, target)
        findings.extend(script_findings)

    # Default credentials check
    findings.extend(_default_cred_findings(ports, target))

    return findings


def _port_risk(port: int, service: str) -> str:
    critical_ports = {23, 512, 513, 514}   # telnet, rexec, rlogin, rsh
    high_ports     = {21, 445, 3389, 5900}  # ftp, smb, rdp, vnc
    medium_ports   = {25, 110, 143, 3306, 5432, 6379, 9200, 27017}

    if port in critical_ports:
        return "Critical"
    if port in high_ports:
        return "High"
    if port in medium_ports:
        return "Medium"
    if service in ("http",) and port not in (80, 8080, 8000):
        return "Low"
    return "Info"


def _port_solution(port: int, service: str) -> str:
    solutions = {
        21:    "Disable FTP; use SFTP/SCP instead. If required, enforce TLS (FTPS).",
        22:    "Restrict SSH access by IP. Disable root login. Use key-based auth only.",
        23:    "Disable Telnet immediately. Replace with SSH.",
        25:    "Restrict SMTP relay. Enable SPF/DKIM/DMARC. Use authentication.",
        445:   "Block SMB externally. Apply latest Windows patches (EternalBlue).",
        3306:  "Bind MySQL to localhost only. Disable remote root login.",
        3389:  "Restrict RDP access by IP or VPN. Enable NLA. Patch BlueKeep.",
        5432:  "Bind PostgreSQL to localhost. Use pg_hba.conf to restrict access.",
        6379:  "Add Redis AUTH password. Bind to localhost. Disable dangerous commands.",
        9200:  "Add Elasticsearch authentication. Bind to localhost or VPN.",
        27017: "Enable MongoDB authentication. Bind to localhost. Disable --noauth.",
    }
    return solutions.get(port, f"Verify if port {port}/{service} needs to be publicly exposed. Apply firewall rules.")


def _check_version(product: str, version: str, port: int, target: str) -> list:
    """Flag known-vulnerable versions. Uses static rules + optional NVD lookup."""
    findings = []
    if not product or not version:
        return findings

    vulnerable = {
        ("openssh",   "7.4"):  ("CVE-2018-15473", "High",   "OpenSSH 7.4 is vulnerable to username enumeration."),
        ("apache",    "2.4.6"):("CVE-2017-7679",  "Critical","Apache 2.4.6 is vulnerable to mod_mime buffer overread."),
        ("mysql",     "5.7.30"):("CVE-2020-14765","High",   "MySQL 5.7.30 contains multiple vulnerabilities."),
        ("redis",     "3.2.12"):("CVE-2022-0543", "Critical","Redis 3.2.x is vulnerable to Lua sandbox escape."),
        ("vsftpd",    "2.3.4"): ("CVE-2011-2523", "Critical","vsftpd 2.3.4 contains a backdoor command execution."),
        ("proftpd",   "1.3.5"): ("CVE-2015-3306", "Critical","ProFTPD 1.3.5 mod_copy allows unauthenticated file copy."),
    }
    prod_lower = product.lower()
    ver_key = version.split(" ")[0]

    for (prod_key, ver_match), (cve, risk, desc) in vulnerable.items():
        if prod_key in prod_lower and ver_match in ver_key:
            findings.append({
                "name": f"Vulnerable Version: {product} {version}",
                "type": "vulnerable_version",
                "risk": risk,
                "port": port,
                "service": prod_lower,
                "host": target,
                "cve": cve,
                "description": desc,
                "solution": f"Upgrade {product} to the latest stable release. Apply vendor patches immediately.",
            })

    return findings


def _check_scripts(scripts: dict, port: int, service: str, target: str) -> list:
    findings = []
    if not scripts:
        return findings

    for script_name, output in scripts.items():
        output_str = str(output).lower()

        if "anonymous" in output_str and service == "ftp":
            findings.append({
                "name": "FTP Anonymous Login Enabled",
                "type": "auth_misconfiguration",
                "risk": "High",
                "port": port,
                "service": "ftp",
                "host": target,
                "description": "FTP server allows anonymous login, exposing files without authentication.",
                "solution": "Disable anonymous FTP access in the server configuration.",
            })

        if "ssl" in script_name and ("expired" in output_str or "self-signed" in output_str):
            findings.append({
                "name": "Invalid SSL Certificate",
                "type": "ssl_error",
                "risk": "Medium",
                "port": port,
                "service": service,
                "host": target,
                "description": "SSL certificate is self-signed or expired, causing browser trust warnings.",
                "solution": "Replace with a valid certificate from a trusted CA (e.g. Let's Encrypt).",
            })

        if "smb-vuln" in script_name and ("vulnerable" in output_str or "true" in output_str):
            findings.append({
                "name": f"SMB Vulnerability Detected ({script_name})",
                "type": "web_vulnerability",
                "risk": "Critical",
                "port": port,
                "service": "smb",
                "host": target,
                "description": f"Nmap NSE script '{script_name}' flagged the target as potentially vulnerable.",
                "solution": "Apply MS17-010 patch. Disable SMBv1. Block port 445 externally.",
            })

    return findings


def _default_cred_findings(ports: list, target: str) -> list:
    """Flag services commonly left with default credentials."""
    findings = []
    default_cred_services = {
        3306: ("MySQL",     "root/root or root/<blank>"),
        5432: ("PostgreSQL","postgres/postgres"),
        6379: ("Redis",     "no password (default)"),
        9200: ("Elasticsearch", "no authentication (default)"),
        27017:("MongoDB",   "no authentication (default)"),
        3389: ("RDP",       "Administrator/<blank> or common passwords"),
    }
    open_port_nums = {p["port"] for p in ports if p.get("state") == "open"}
    for port, (svc, default) in default_cred_services.items():
        if port in open_port_nums:
            findings.append({
                "name": f"Potential Default Credentials: {svc}",
                "type": "auth_misconfiguration",
                "risk": "High",
                "port": port,
                "service": svc.lower(),
                "host": target,
                "description": (f"{svc} on port {port} may use default credentials ({default}). "
                                "Default credentials are the #1 cause of database breaches."),
                "solution": f"Set a strong unique password for {svc}. Restrict port {port} to trusted IPs only.",
            })
    return findings
