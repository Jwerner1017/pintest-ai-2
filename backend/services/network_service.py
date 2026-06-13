"""Network analysis via nmap host discovery + service mapping."""
import asyncio
import logging
import shutil

logger = logging.getLogger(__name__)

NMAP_AVAILABLE = shutil.which("nmap") is not None

try:
    import nmap
except ImportError:
    nmap = None


# Heuristics for "weak" services seen on a host.
WEAK_SERVICES = {
    "telnet": ("high", "Telnet transmits credentials in plaintext."),
    "ftp": ("medium", "FTP exposed — verify anonymous login is disabled and prefer SFTP."),
    "rsh": ("high", "rsh/rlogin uses no encryption."),
    "rlogin": ("high", "rlogin transmits credentials in plaintext."),
    "smb": ("medium", "SMB exposed — ensure SMBv1 is disabled."),
    "vnc": ("medium", "VNC exposed — verify strong auth or restrict to VPN."),
    "rdp": ("medium", "RDP exposed — enable NLA and restrict by IP."),
    "snmp": ("medium", "SNMP exposed — verify default communities are not used."),
}


async def run_network_scan(target: str, options: dict | None = None) -> dict:
    """Discover live hosts in `target` (CIDR or single host) and map services."""
    options = options or {}
    progress_cb = options.get("progress_cb")
    discovery_args = options.get("discovery_args", "-sn -T4 -PS22,80,443 --host-timeout 30s")
    service_args = options.get("service_args", "-sT -sV -T4 --top-ports 50 -Pn --host-timeout 60s")

    if not (NMAP_AVAILABLE and nmap):
        return {
            "target": target,
            "scan_type": "network_analysis",
            "scan_engine": "mock",
            "mock_reason": "nmap binary not installed",
            "alive_hosts": [],
            "anomalies": [],
            "traffic_summary": {"total_packets": 0, "protocols": {}, "top_talkers": []},
        }

    if progress_cb:
        await progress_cb(10, "Discovering live hosts")

    try:
        alive = await asyncio.to_thread(_nmap_ping_sweep_blocking, target, discovery_args)
    except Exception as e:  # noqa: BLE001
        logger.warning("nmap ping sweep failed: %s", e)
        alive = []

    if progress_cb:
        await progress_cb(40, f"Found {len(alive)} hosts; mapping services")

    host_data: list[dict] = []
    if alive:
        try:
            host_data = await asyncio.to_thread(_nmap_service_map_blocking, alive, service_args)
        except Exception as e:  # noqa: BLE001
            logger.warning("nmap service map failed: %s", e)

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
            # Synthesized values; container has no packet capture capability.
            "total_packets": 0,
            "protocols": {},
            "top_talkers": [],
        },
    }


def _nmap_ping_sweep_blocking(target: str, args: str) -> list[str]:
    scanner = nmap.PortScanner()
    try:
        scanner.scan(hosts=target, arguments=args)
        alive = [h for h in scanner.all_hosts() if scanner[h].state() == "up"]
    except Exception:  # noqa: BLE001
        alive = []

    if not alive and "/" not in target and "-" not in target:
        alive = [target]
    return alive


def _nmap_service_map_blocking(hosts: list[str], args: str) -> list[dict]:
    scanner = nmap.PortScanner()
    targets = " ".join(hosts[:32])
    scanner.scan(hosts=targets, arguments=args)

    results: list[dict] = []
    for h in scanner.all_hosts():
        ports = []
        for proto in scanner[h].all_protocols():
            for port in scanner[h][proto]:
                info = scanner[h][proto][port]
                if info.get("state") != "open":
                    continue
                ports.append({
                    "port": port,
                    "protocol": proto,
                    "service": info.get("name", "unknown"),
                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip() or "unknown",
                })
        results.append({
            "ip": h,
            "hostname": scanner[h].hostname() or h,
            "ports": ports,
        })
    return results


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
        # Flag hosts with many open ports as "wide attack surface"
        if len(host.get("ports", [])) >= 10:
            anomalies.append({
                "type": "Wide attack surface",
                "severity": "medium",
                "host": host["ip"],
                "description": f"{len(host['ports'])} open ports — review necessity of each.",
            })
    return anomalies
