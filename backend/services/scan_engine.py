"""Shared scan dispatcher for POST /scans and bulk/scheduled jobs."""
from services import distros as distros_service
from services import network_service, nmap_service, presets as presets_service, vuln_service


async def run_scan_engine(scan_type: str, target: str, options: dict | None = None, progress_cb=None) -> dict:
    options = options or {}
    preset_name = options.get("preset")
    preset_cfg = presets_service.get_preset(scan_type, preset_name)
    merged = {**preset_cfg, **{k: v for k, v in options.items() if v is not None}}
    if progress_cb is not None:
        merged["progress_cb"] = progress_cb
    if progress_cb:
        await progress_cb(5, f"Starting ({preset_cfg.get('label', 'default')})")
    if scan_type == "recon":
        results = await nmap_service.run_recon_scan(target, merged)
    elif scan_type == "vuln":
        results = await vuln_service.run_vuln_scan(target, merged)
    elif scan_type == "network":
        results = await network_service.run_network_scan(target, merged)
    else:
        results = {"target": target, "scan_type": scan_type, "scan_engine": "unknown"}
    if results is not None:
        results["preset"] = preset_name or presets_service.DEFAULT_PRESET
        results["recommended_distros"] = distros_service.recommend_for(scan_type)
    return results
