"""
Network Agent — Nmap with auth support + PoC evidence capture.
Tool label: Nmap 7.x (real) | Mock scanner (fallback)
"""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

TOOL_NAME    = "Nmap 7.x"
TOOL_FALLBACK = "Mock Network Scanner"

DEEP_SCAN_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017"

MOCK_HOSTS = [{
    "hostname": "target", "ip": "192.168.1.1", "state": "up",
    "ports": [
        {"port":22,   "state":"open","service":"ssh",    "product":"OpenSSH",    "version":"7.4",   "cpe":"cpe:/a:openbsd:openssh:7.4",   "script_output":{}},
        {"port":80,   "state":"open","service":"http",   "product":"Apache httpd","version":"2.4.6","cpe":"cpe:/a:apache:http_server:2.4.6","script_output":{}},
        {"port":443,  "state":"open","service":"https",  "product":"Apache httpd","version":"2.4.6","cpe":"cpe:/a:apache:http_server:2.4.6","script_output":{}},
        {"port":3306, "state":"open","service":"mysql",  "product":"MySQL",       "version":"5.7.30","cpe":"",                               "script_output":{}},
        {"port":6379, "state":"open","service":"redis",  "product":"Redis",       "version":"3.2.12","cpe":"",                               "script_output":{}},
    ]
}]


def run_network_scan(target: str, recon_data: dict, config=None, checklist_items=None) -> dict:
    logger.info(f"[NETWORK] Starting network scan: {target}")
    start = datetime.utcnow()
    host  = recon_data.get("ip_address") or recon_data.get("hostname") or target

    extra_args = ""
    ports      = DEEP_SCAN_PORTS
    if config:
        if config.nmap_extra_args: extra_args = config.nmap_extra_args
        if config.nmap_ports:      ports      = config.nmap_ports
        if config.username and config.password:
            extra_args += f" --script-args 'user={config.username},pass={config.password}'"

    scan_data, tool_used = _run_nmap(host, ports, extra_args)
    findings = []
    for host_info in scan_data.get("hosts", []):
        findings.extend(_analyse_host(host_info, target))

    return {
        "module":     "network",
        "target":     target,
        "tool_used":  tool_used,
        "scan_time":  (datetime.utcnow() - start).total_seconds(),
        "raw_nmap":   scan_data,
        "findings":   findings,
        "auth_used":  config.build_auth_summary() if config else "Unauthenticated",
    }


def _run_nmap(host: str, ports: str, extra_args: str) -> tuple:
    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        args = f"-sV -sC --open -T4 --host-timeout 120s {extra_args}".strip()
        logger.info(f"[NETWORK] nmap {args} -p {ports} {host}")
        nm.scan(hosts=host, ports=ports, arguments=args)
        hosts_data = []
        for h in nm.all_hosts():
            hi = {"hostname": nm[h].hostname() or h, "ip": h,
                  "state": nm[h].state(), "ports": []}
            for proto in nm[h].all_protocols():
                for port, data in nm[h][proto].items():
                    if data["state"] == "open":
                        hi["ports"].append({
                            "port": port, "state": data["state"],
                            "service": data.get("name","unknown"),
                            "product": data.get("product",""),
                            "version": data.get("version",""),
                            "extrainfo": data.get("extrainfo",""),
                            "cpe": " ".join(data.get("cpe",[])),
                            "script_output": data.get("script",{}),
                        })
            hosts_data.append(hi)
        return {"source": "nmap", "hosts": hosts_data}, TOOL_NAME
    except ImportError:
        logger.warning("[NETWORK] python-nmap not installed — mock data")
        return {"source": "mock", "hosts": MOCK_HOSTS}, TOOL_FALLBACK
    except Exception as e:
        logger.error(f"[NETWORK] Nmap error: {e}")
        return {"source": "mock_fallback", "hosts": MOCK_HOSTS, "error": str(e)}, TOOL_FALLBACK


def _analyse_host(host_info: dict, target: str) -> list:
    findings = []
    for p in host_info.get("ports", []):
        port, service = p["port"], p.get("service","unknown")
        product, version = p.get("product",""), p.get("version","")
        ip = host_info.get("ip", target)

        poc_curl = _build_port_poc(ip, port, service)

        findings.append({
            "name":     f"Open Port: {port}/{service}",
            "type":     "open_port",
            "risk":     _port_risk(port, service),
            "port":     port, "service": service,
            "product":  product, "version": version,
            "host":     ip,
            "url":      f"{ip}:{port}",   # schema: consistent url field across all modules
            "description": (f"Port {port}/{service} is open"
                            + (f" running {product} {version}".rstrip() if product else "") + "."),
            "solution": _port_solution(port, service),
            "evidence": {
                "type":     "port_open",
                "curl_poc": poc_curl,
                "banner":   f"{product} {version}".strip(),
                "nmap_cmd": f"nmap -sV -p {port} {ip}",
            },
        })

        findings.extend(_check_version(product, version, port, ip))
        findings.extend(_check_scripts(p.get("script_output",{}), port, service, ip))

    findings.extend(_default_cred_findings(host_info.get("ports",[]), target))
    return findings


def _build_port_poc(host: str, port: int, service: str) -> str:
    templates = {
        "http":   f'curl -sk "http://{host}:{port}/"',
        "https":  f'curl -sk "https://{host}:{port}/"',
        "ftp":    f'ftp {host} {port}',
        "ssh":    f'ssh -p {port} user@{host}',
        "mysql":  f'mysql -h {host} -P {port} -u root -p',
        "redis":  f'redis-cli -h {host} -p {port} PING',
        "mongodb":f'mongo --host {host} --port {port}',
    }
    return templates.get(service, f'nc -zv {host} {port}')


def _port_risk(port: int, service: str) -> str:
    if port in {23, 512, 513, 514}:                  return "Critical"
    if port in {21, 445, 3389, 5900}:                return "High"
    if port in {25, 110, 143, 3306, 5432, 6379, 9200, 27017}: return "Medium"
    return "Low"


def _port_solution(port: int, service: str) -> str:
    return {
        21:    "Disable FTP; use SFTP. If required, enforce TLS (FTPS).",
        22:    "Restrict SSH by IP. Disable root login. Use key-based auth only.",
        23:    "Disable Telnet immediately. Replace with SSH.",
        445:   "Block SMB externally. Apply EternalBlue patches.",
        3306:  "Bind MySQL to localhost. Disable remote root login.",
        3389:  "Restrict RDP to VPN/IP whitelist. Enable NLA.",
        5432:  "Bind PostgreSQL to localhost. Use pg_hba.conf restrictions.",
        6379:  "Add Redis AUTH password. Bind to localhost.",
        9200:  "Add Elasticsearch auth. Bind to localhost or VPN.",
        27017: "Enable MongoDB auth. Bind to localhost. Disable --noauth.",
    }.get(port, f"Verify port {port}/{service} needs public exposure. Apply firewall rules.")


def _check_version(product: str, version: str, port: int, target: str) -> list:
    if not product or not version:
        return []
    vuln_db = {
        ("openssh",  "7.4"):   ("CVE-2018-15473","High",   "OpenSSH 7.4 — username enumeration via timing attack."),
        ("apache",   "2.4.6"): ("CVE-2017-7679", "Critical","Apache 2.4.6 — mod_mime buffer overread, potential RCE."),
        ("mysql",    "5.7.30"):("CVE-2020-14765","High",   "MySQL 5.7.30 — multiple high-severity vulnerabilities."),
        ("redis",    "3.2.12"):("CVE-2022-0543", "Critical","Redis 3.2.x — Lua sandbox escape, unauthenticated RCE."),
        ("vsftpd",   "2.3.4"): ("CVE-2011-2523", "Critical","vsftpd 2.3.4 — backdoor on port 6200 after :) in username."),
        ("proftpd",  "1.3.5"): ("CVE-2015-3306", "Critical","ProFTPD 1.3.5 mod_copy — unauthenticated file copy/read."),
    }
    prod_lower = product.lower()
    ver_key    = version.split(" ")[0]
    findings   = []
    for (pk, vm), (cve, risk, desc) in vuln_db.items():
        if pk in prod_lower and vm in ver_key:
            findings.append({
                "name":    f"Vulnerable Version: {product} {version}",
                "type":    "vulnerable_version",
                "risk":    risk,
                "port":    port, "service": prod_lower, "host": target,
                "cve":     cve,
                "description": desc,
                "solution": f"Upgrade {product} to latest stable immediately.",
                "evidence": {
                    "type":    "version_detection",
                    "banner":  f"{product} {version}",
                    "cve":     cve,
                    "nmap_cmd": f"nmap -sV -p {port} {target}",
                    "curl_poc": f'curl -sk "http://{target}:{port}/" -I',
                },
            })
    return findings


def _check_scripts(scripts: dict, port: int, service: str, target: str) -> list:
    findings = []
    for script_name, output in (scripts or {}).items():
        out = str(output).lower()
        if "anonymous" in out and service == "ftp":
            findings.append({
                "name": "FTP Anonymous Login Enabled", "type": "auth_misconfiguration",
                "risk": "High", "port": port, "service": "ftp", "host": target,
                "description": "FTP allows anonymous login — no auth required to access files.",
                "solution": "Disable anonymous FTP in server config.",
                "evidence": {
                    "type":    "auth_bypass",
                    "curl_poc": f"ftp {target} {port}  # login: anonymous / anonymous",
                    "raw_response": str(output)[:500],
                },
            })
        if "ssl" in script_name and ("expired" in out or "self-signed" in out):
            findings.append({
                "name": "Invalid SSL Certificate", "type": "ssl_error",
                "risk": "Medium", "port": port, "host": target,
                "description": "SSL cert is self-signed or expired — MITM risk.",
                "solution": "Replace with a valid CA-signed certificate (e.g. Let's Encrypt).",
                "evidence": {
                    "type":    "ssl_issue",
                    "curl_poc": f'openssl s_client -connect {target}:{port}',
                    "raw_response": str(output)[:500],
                },
            })
        if "smb-vuln" in script_name and ("vulnerable" in out or "true" in out):
            findings.append({
                "name": f"SMB Vulnerability ({script_name})", "type": "web_vulnerability",
                "risk": "Critical", "port": port, "service": "smb", "host": target,
                "description": f"Nmap NSE {script_name} confirms SMB vulnerability.",
                "solution": "Apply MS17-010 patch. Disable SMBv1. Block 445 externally.",
                "evidence": {
                    "type":    "smb_vuln",
                    "nmap_cmd": f"nmap --script={script_name} -p 445 {target}",
                    "raw_response": str(output)[:500],
                },
            })
    return findings


def _default_cred_findings(ports: list, target: str) -> list:
    findings = []
    cred_map = {
        3306: ("MySQL",         "root / <blank>",  f"mysql -h {target} -u root -p"),
        5432: ("PostgreSQL",    "postgres/postgres",f"psql -h {target} -U postgres"),
        6379: ("Redis",         "no auth (default)",f"redis-cli -h {target} PING"),
        9200: ("Elasticsearch", "no auth (default)",f'curl -sk "http://{target}:9200/_cat/indices"'),
        27017:("MongoDB",       "no auth (default)",f"mongo --host {target}"),
        3389: ("RDP",           "Administrator/<blank>","mstsc /v:{target}"),
    }
    open_ports = {p["port"] for p in ports if p.get("state") == "open"}
    for port, (svc, creds, poc) in cred_map.items():
        if port in open_ports:
            findings.append({
                "name":    f"Potential Default Credentials: {svc}",
                "type":    "auth_misconfiguration",
                "risk":    "High",
                "port":    port, "service": svc.lower(), "host": target,
                "description": f"{svc}:{port} may use default credentials ({creds}).",
                "solution": f"Set a strong unique password. Restrict port {port} to trusted IPs.",
                "evidence": {
                    "type":    "default_creds",
                    "curl_poc": poc,
                    "default_creds": creds,
                },
            })
    return findings
