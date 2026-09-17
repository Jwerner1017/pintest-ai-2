import asyncio, os, sys
from pathlib import Path
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("JWT_SECRET", "test")
os.environ.setdefault("MONGO_URL", "mongodb://127.0.0.1:27017")
os.environ.setdefault("DB_NAME", "pintest_boot_test")
os.environ["PENTESTAI_DISABLE_SCHEDULER"] = "1"

def test_compat_does_not_import_legacy_scanner():
    import routers.compat as compat
    source = Path(compat.__file__).read_text()
    assert "perform_recon_scan" not in source
    assert "run_scan_engine" in source

def test_run_scan_engine_dispatches_recon(monkeypatch):
    from routers import scans as scans_router
    async def fake_recon(target, options):
        return {"target": target, "scan_engine": "nmap", "ports": []}
    async def boom(*a, **k):
        raise AssertionError("wrong service")
    monkeypatch.setattr(scans_router.nmap_service, "run_recon_scan", fake_recon)
    monkeypatch.setattr(scans_router.vuln_service, "run_vuln_scan", boom)
    monkeypatch.setattr(scans_router.network_service, "run_network_scan", boom)
    result = asyncio.run(scans_router.run_scan_engine("recon", "example.com", {"preset": "fast"}))
    assert result["scan_engine"] == "nmap"
