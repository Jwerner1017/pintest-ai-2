"""Shodan host intel service."""
import os
import logging
import asyncio

logger = logging.getLogger(__name__)

try:
    import shodan  # shodan library
except ImportError:
    shodan = None


def is_configured() -> bool:
    return bool(os.environ.get("SHODAN_API_KEY")) and shodan is not None


async def host_lookup(target: str) -> dict:
    """Look up a host on Shodan. `target` must be an IP (Shodan does not resolve domains)."""
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {
            "target": target,
            "scan_engine": "shodan",
            "configured": False,
            "message": "SHODAN_API_KEY not configured on backend",
            "services": [],
        }
    if shodan is None:
        return {
            "target": target,
            "scan_engine": "shodan",
            "configured": False,
            "message": "shodan python package missing",
            "services": [],
        }

    try:
        data = await asyncio.to_thread(_shodan_host_blocking, api_key, target)
        return data
    except Exception as e:  # noqa: BLE001
        logger.warning("shodan lookup failed for %s: %s", target, e)
        return {
            "target": target,
            "scan_engine": "shodan",
            "configured": True,
            "error": str(e),
            "services": [],
        }


def _shodan_host_blocking(api_key: str, target: str) -> dict:
    api = shodan.Shodan(api_key)
    host = api.host(target)

    services = []
    for svc in host.get("data", []):
        services.append({
            "port": svc.get("port"),
            "transport": svc.get("transport", "tcp"),
            "product": svc.get("product"),
            "version": svc.get("version"),
            "banner": (svc.get("data", "") or "")[:500],
        })

    return {
        "target": target,
        "scan_engine": "shodan",
        "configured": True,
        "ip_str": host.get("ip_str"),
        "org": host.get("org"),
        "isp": host.get("isp"),
        "country": host.get("country_name"),
        "city": host.get("city"),
        "os": host.get("os"),
        "hostnames": host.get("hostnames", []),
        "ports": host.get("ports", []),
        "vulns": list(host.get("vulns", [])) if host.get("vulns") else [],
        "tags": host.get("tags", []),
        "last_update": host.get("last_update"),
        "services": services,
    }
