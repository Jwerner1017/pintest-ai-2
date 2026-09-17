"""NVD CVE enrichment — query NIST NVD API for CVEs matching service banners.

Caches results in `cve_cache` collection to stay under rate limits and speed up repeat scans.
NVD allows 5 requests/30s anonymous, 50/30s with API key (NVD_API_KEY env var).
"""
import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta

import requests

from core.db import db

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_HOURS = 24


def is_enabled() -> bool:
    return os.environ.get("NVD_ENRICHMENT_DISABLED", "").lower() not in ("1", "true", "yes")


async def enrich_ports(ports: list[dict]) -> list[dict]:
    """For each port with a non-empty version string, attach a `cves` list.

    Returns a flat list of CVE findings suitable to merge into vulnerabilities[].
    """
    if not is_enabled() or not ports:
        return []

    findings: list[dict] = []
    seen_keys = set()
    for port in ports:
        product = (port.get("product") or "").strip()
        version = (port.get("version") or "").strip()
        service = (port.get("service") or "").strip()
        # Build a search keyword from the most specific info we have.
        if product and version:
            kw = f"{product} {version}"
        elif version and service:
            kw = f"{service} {version}"
        else:
            continue
        kw_key = kw.lower()
        if kw_key in seen_keys:
            continue
        seen_keys.add(kw_key)

        cves = await _lookup_cves(kw)
        for cve in cves[:5]:  # cap at 5 per service
            findings.append({
                "id": cve["id"],
                "severity": cve["severity"],
                "description": f"[port {port.get('port')}/{service}] {cve['summary']}",
                "source": "nvd",
                "cvss": cve.get("cvss"),
                "references": cve.get("references", [])[:3],
                "remediation": f"Patch {product or service} to a version newer than {version}.",
            })
    return findings


async def _lookup_cves(keyword: str) -> list[dict]:
    """Look up CVEs matching `keyword`. Cached for 24h."""
    cached = await db.cve_cache.find_one({"keyword": keyword.lower()}, {"_id": 0})
    if cached and _fresh(cached.get("cached_at")):
        return cached.get("cves", [])

    try:
        cves = await asyncio.to_thread(_query_nvd, keyword)
    except Exception as e:  # noqa: BLE001
        logger.warning("NVD lookup failed for %r: %s", keyword, e)
        return []

    await db.cve_cache.update_one(
        {"keyword": keyword.lower()},
        {"$set": {
            "keyword": keyword.lower(),
            "cves": cves,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }},
        upsert=True,
    )
    return cves


def _fresh(cached_at: str | None) -> bool:
    if not cached_at:
        return False
    try:
        when = datetime.fromisoformat(cached_at)
    except Exception:
        return False
    return datetime.now(timezone.utc) - when < timedelta(hours=CACHE_TTL_HOURS)


def _query_nvd(keyword: str) -> list[dict]:
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=15)
    resp.raise_for_status()
    payload = resp.json()

    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # Pull description (English first available).
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:300]
                break

        # CVSS — prefer v3.1 then v3 then v2.
        cvss = None
        severity = "info"
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                metric = arr[0]
                cvss_data = metric.get("cvssData", {})
                cvss = cvss_data.get("baseScore")
                severity = (metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "").lower() or "info"
                break

        # References.
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        out.append({
            "id": cve_id,
            "summary": desc,
            "cvss": cvss,
            "severity": severity if severity in ("critical", "high", "medium", "low", "info") else "info",
            "references": refs,
        })
    return out
