"""
Real Network Scanner Module for PentestAI
Performs actual network reconnaissance using Python libraries.
"""
import socket
import asyncio
import dns.resolver
import whois
from datetime import datetime, timezone
from typing import Optional
import logging
import re

logger = logging.getLogger(__name__)

# Common ports to scan
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb"
}


def is_valid_target(target: str) -> bool:
    """Validate if target is a valid domain or IP address."""
    # Check if it's an IP address
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(target):
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    
    # Check if it's a valid domain
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')
    return bool(domain_pattern.match(target))


async def scan_port(host: str, port: int, timeout: float = 2.0) -> dict:
    """Scan a single port on the target host."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return {
            "port": port,
            "service": COMMON_PORTS.get(port, "unknown"),
            "state": "open",
            "version": "unknown"
        }
    except asyncio.TimeoutError:
        return {
            "port": port,
            "service": COMMON_PORTS.get(port, "unknown"),
            "state": "filtered",
            "version": "unknown"
        }
    except (ConnectionRefusedError, OSError):
        return None  # Port is closed, don't include in results


async def scan_ports(host: str, ports: list = None) -> list:
    """Scan multiple ports concurrently."""
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    tasks = [scan_port(host, port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    # Filter out None (closed ports) and return only open/filtered
    return [r for r in results if r is not None]


def resolve_hostname(target: str) -> Optional[str]:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def get_dns_records(domain: str) -> list:
    """Get various DNS records for a domain."""
    records = []
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                value = str(rdata)
                # For MX records, extract just the exchange
                if record_type == 'MX':
                    value = str(rdata.exchange).rstrip('.')
                elif record_type == 'NS':
                    value = str(rdata.target).rstrip('.')
                elif record_type == 'SOA':
                    value = str(rdata.mname).rstrip('.')
                records.append({
                    "type": record_type,
                    "value": value
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
            continue
    
    return records


def get_whois_info(domain: str) -> dict:
    """Get WHOIS information for a domain."""
    try:
        w = whois.whois(domain)
        
        # Handle dates that might be lists
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        return {
            "registrar": w.registrar or "Unknown",
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else "Unknown",
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else "Unknown",
            "name_servers": w.name_servers[:3] if w.name_servers else [],
            "status": w.status[:2] if w.status else [],
            "registrant_country": w.country or "Unknown"
        }
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return {
            "registrar": "Unable to retrieve",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "name_servers": [],
            "status": [],
            "registrant_country": "Unknown"
        }


def detect_os_from_ports(open_ports: list) -> str:
    """Basic OS detection based on open ports."""
    port_numbers = [p['port'] for p in open_ports]
    
    if 445 in port_numbers and 135 in port_numbers:
        return "Windows (detected via SMB/RPC)"
    if 22 in port_numbers and 80 in port_numbers:
        return "Linux/Unix (detected via SSH/HTTP)"
    if 22 in port_numbers:
        return "Likely Linux/Unix (SSH detected)"
    if 3389 in port_numbers:
        return "Windows (RDP detected)"
    if 80 in port_numbers or 443 in port_numbers:
        return "Web server (OS undetermined)"
    
    return "Unknown"


def analyze_vulnerabilities(target: str, ports: list, dns_records: list) -> list:
    """Analyze potential vulnerabilities based on scan results."""
    vulnerabilities = []
    port_numbers = [p['port'] for p in ports]
    
    # Check for potentially dangerous open ports
    if 21 in port_numbers:
        vulnerabilities.append({
            "id": "PENTEST-FTP-001",
            "severity": "medium",
            "description": "FTP port (21) is open. FTP transmits data in plaintext and may be vulnerable to credential sniffing.",
            "cvss": 5.3,
            "remediation": "Use SFTP or FTPS instead of plain FTP"
        })
    
    if 23 in port_numbers:
        vulnerabilities.append({
            "id": "PENTEST-TELNET-001",
            "severity": "high",
            "description": "Telnet port (23) is open. Telnet is unencrypted and should not be used.",
            "cvss": 7.5,
            "remediation": "Disable Telnet and use SSH for remote access"
        })
    
    if 3389 in port_numbers:
        vulnerabilities.append({
            "id": "PENTEST-RDP-001",
            "severity": "high",
            "description": "RDP port (3389) is exposed to the internet. This is a common attack vector.",
            "cvss": 7.8,
            "remediation": "Restrict RDP access via VPN or firewall rules"
        })
    
    if 27017 in port_numbers:
        vulnerabilities.append({
            "id": "PENTEST-MONGO-001",
            "severity": "critical",
            "description": "MongoDB port (27017) is exposed. May allow unauthorized database access.",
            "cvss": 9.1,
            "remediation": "Enable authentication and restrict network access"
        })
    
    if 6379 in port_numbers:
        vulnerabilities.append({
            "id": "PENTEST-REDIS-001",
            "severity": "critical",
            "description": "Redis port (6379) is exposed. Redis often runs without authentication.",
            "cvss": 9.1,
            "remediation": "Enable Redis authentication and bind to localhost"
        })
    
    if 3306 in port_numbers:
        vulnerabilities.append({
            "id": "PENTEST-MYSQL-001",
            "severity": "high",
            "description": "MySQL port (3306) is exposed to the internet.",
            "cvss": 7.5,
            "remediation": "Restrict MySQL access to trusted IPs only"
        })
    
    # Check if both HTTP and HTTPS are available
    if 80 in port_numbers and 443 not in port_numbers:
        vulnerabilities.append({
            "id": "PENTEST-HTTPS-001",
            "severity": "medium",
            "description": "HTTP is available but HTTPS is not detected. Data may be transmitted unencrypted.",
            "cvss": 5.0,
            "remediation": "Enable HTTPS and redirect all HTTP traffic"
        })
    
    # DNS record analysis
    txt_records = [r for r in dns_records if r['type'] == 'TXT']
    has_spf = any('spf' in r['value'].lower() for r in txt_records)
    has_dmarc = any('dmarc' in r['value'].lower() for r in txt_records)
    
    if not has_spf:
        vulnerabilities.append({
            "id": "PENTEST-SPF-001",
            "severity": "low",
            "description": "No SPF record found. Domain may be susceptible to email spoofing.",
            "cvss": 3.7,
            "remediation": "Add an SPF TXT record to prevent email spoofing"
        })
    
    return vulnerabilities


async def perform_recon_scan(target: str) -> dict:
    """Perform a full reconnaissance scan on the target."""
    if not is_valid_target(target):
        return {"error": f"Invalid target: {target}"}
    
    results = {
        "target": target,
        "scan_type": "reconnaissance",
        "scan_started": datetime.now(timezone.utc).isoformat(),
        "ports": [],
        "os_detection": "Unknown",
        "hostnames": [target],
        "ip_address": None,
        "whois": {},
        "dns_records": [],
        "vulnerabilities": []
    }
    
    # Resolve hostname to IP
    ip = resolve_hostname(target)
    if ip:
        results["ip_address"] = ip
        if ip != target:
            results["hostnames"].append(ip)
    else:
        results["ip_address"] = "Unable to resolve"
    
    # Get DNS records
    try:
        results["dns_records"] = get_dns_records(target)
    except Exception as e:
        logger.warning(f"DNS lookup failed: {e}")
    
    # Get WHOIS info
    results["whois"] = get_whois_info(target)
    
    # Port scan (using resolved IP if available)
    scan_target = ip if ip else target
    try:
        results["ports"] = await scan_ports(scan_target)
    except Exception as e:
        logger.warning(f"Port scan failed: {e}")
    
    # OS detection
    results["os_detection"] = detect_os_from_ports(results["ports"])
    
    # Vulnerability analysis
    results["vulnerabilities"] = analyze_vulnerabilities(
        target, 
        results["ports"], 
        results["dns_records"]
    )
    
    results["scan_completed"] = datetime.now(timezone.utc).isoformat()
    
    return results


def generate_vuln_scan_results(target: str, ports: list = None) -> dict:
    """Generate vulnerability scan results based on target analysis."""
    vulnerabilities = []
    
    if ports:
        vulnerabilities.extend(analyze_vulnerabilities(target, ports, []))
    
    # Add some common web vulnerabilities for educational purposes
    vulnerabilities.extend([
        {
            "id": "OWASP-A01",
            "severity": "high",
            "description": "Potential Broken Access Control - Verify authorization checks on all endpoints",
            "cvss": 8.6,
            "remediation": "Implement proper access control checks on server side"
        },
        {
            "id": "OWASP-A03",
            "severity": "high",
            "description": "Injection vulnerabilities should be tested - SQL, NoSQL, Command injection",
            "cvss": 8.6,
            "remediation": "Use parameterized queries and input validation"
        },
        {
            "id": "OWASP-A07",
            "severity": "medium",
            "description": "Cross-Site Scripting (XSS) - Test all user input fields",
            "cvss": 6.1,
            "remediation": "Implement Content-Security-Policy and sanitize outputs"
        }
    ])
    
    # Calculate risk score
    severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2}
    total_weight = sum(severity_weights.get(v.get("severity", "low"), 1) for v in vulnerabilities)
    risk_score = min(10.0, total_weight / len(vulnerabilities) if vulnerabilities else 0)
    
    return {
        "target": target,
        "scan_type": "vulnerability",
        "vulnerabilities": vulnerabilities,
        "risk_score": round(risk_score, 1),
        "compliance": {
            "pci_dss": "Assessment required",
            "owasp_top10": ["A01:2021 - Broken Access Control", "A03:2021 - Injection", "A07:2021 - XSS"]
        }
    }


def generate_network_scan_results(target: str) -> dict:
    """Generate network analysis results (simulated for safety)."""
    return {
        "target": target,
        "scan_type": "network_analysis",
        "mocked": True,
        "traffic_summary": {
            "total_packets": 0,
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0},
            "top_talkers": [],
            "note": "Live traffic capture requires elevated privileges"
        },
        "anomalies": [],
        "vulnerabilities": [],
        "recommendation": "For real network analysis, use Wireshark or tcpdump with proper authorization"
    }
