"""Network analysis via nmap host discovery + service mapping."""
import logging

from services import nmap_runner

logger = logging.getLogger(__name__)


WEAK_SERVICES = {
    "telnet": ("high", "Telnet transmits credentials in plaintext."),
    "ftp": ("medium", "FTP exposed — verify anonymous login is disabled."),
    "rsh": ("high", "rsh/rlogin uses no encryption."),
    "rlogin": ("high", "rlogin transmits credentials in plaintext."),
    "smb": ("medium", "SMB exposed — ensure SMBv1 is disabled."),
    "vnc": ("medium", "VNC exposed — verify strong auth or restrict to VPN."),
    "rdp": ("medium", "RDP exposed — enable NLA and restrict by IP."),
    "snmp": ("medium", "SNMP exposed — verify default communities not in use."),
}


async def run_network_scan(target: str, options: dict | None = None) -> dict:
    """Discover live hosts in `target` (CIDR or single host) and map services."""
    options = options or {}
    progress_cb = options.get("progress_cb")
    discovery_args = options.get("discovery_args", "-sn -T4 -PS22,80,443 --host-timeout 30s")
    service_args = options.get("service_args", "-sT -sV -T4 --top-ports 50 -Pn --host-timeout 60s")

    if not nmap_runner.is_available():
        return {
            "target": target,
            "scan_type": "network_analysis",
            "scan_engine": "mock",
            "mock_reason": "nmap binary not installed",
            "alive_hosts": [],
            "anomalies": [],
            "traffic_summary": {"total_packets": 0, "protocols": {}, "top_talkers": []},
            "nmap_xml": "",
        }

    if progress_cb:
        await progress_cb(10, "Discovering live hosts")

    disc = await nmap_runner.run(target, discovery_args)
    alive = [h["ip"] for h in disc.hosts if h.get("state") == "up" and h.get("ip")]
    # Fallback: single-host targets often fail ping discovery in restrictive containers.
    if not alive and "/" not in target and "-" not in target:
        alive = [target]

    if progress_cb:
        await progress_cb(40, f"Found {len(alive)} hosts; mapping services")

    host_data: list[dict] = []
    raw_xml = disc.raw_xml
    if alive:
        svc_run = await nmap_runner.run(" ".join(alive[:32]), service_args)
        raw_xml = svc_run.raw_xml or raw_xml
        for h in svc_run.hosts:
            open_ports = [
                {
                    "port": p["port"],
                    "protocol": p["protocol"],
                    "service": p["service"],
                    "version": f"{p.get('product') or ''} {p.get('version') or ''}".strip() or "unknown",
                }
                for p in h.get("ports", []) if p.get("state") == "open"
            ]
            host_data.append({
                "ip": h["ip"],
                "hostname": h.get("hostname") or h["ip"],
                "ports": open_ports,
            })

    if progress_cb:
        await progress_cb(85, "Detecting anomalies")

    anomalies = _detect_anomalies(host_data)
    total_open_ports = sum(len(h.get("ports", [])) for h in host_data)

    return {
        "target": target,
        "scan_type": "network_analysis",
        "scan_engine": "nmap",
        "alive_hosts": host_data,
        "anomalies": anomalies,
        "traffic_summary": {
            "hosts_alive": len(alive),
            "hosts_scanned_for_services": len(host_data),
            "total_open_ports": total_open_ports,
            # Synthesized — container has no packet capture capability.
            "total_packets": 0,
            "protocols": {},
            "top_talkers": [],
        },
        "nmap_xml": raw_xml,
    }


def _detect_anomalies(host_data: list[dict]) -> list[dict]:
    anomalies: list[dict] = []
    for host in host_data:
        for p in host.get("ports", []):
            svc = (p.get("service") or "").lower()
            if svc in WEAK_SERVICES:
                sev, msg = WEAK_SERVICES[svc]
                anomalies.append({
                    "type": f"Weak service: {svc.upper()}",
                    "severity": sev,
                    "host": host["ip"],
                    "port": p["port"],
                    "description": msg,
                })
        if len(host.get("ports", [])) >= 10:
            anomalies.append({
                "type": "Wide attack surface",
                "severity": "medium",
                "host": host["ip"],
                "description": f"{len(host['ports'])} open ports — review necessity of each.",
            })
    return anomalies
