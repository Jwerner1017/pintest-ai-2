import os, sys
from pathlib import Path
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("JWT_SECRET", "test")
os.environ.setdefault("MONGO_URL", "mongodb://127.0.0.1:27017")
os.environ.setdefault("DB_NAME", "pintest_boot_test")
os.environ["PENTESTAI_DISABLE_SCHEDULER"] = "1"

def test_server_module_imports():
    import server
    assert server.app.version == "2.0.0"

def test_required_paths_are_mounted():
    import server
    from routers import compat
    spec = set(server.app.openapi()["paths"])
    for path in ("/api/auth/register", "/api/scans", "/api/bulk-scans", "/api/scans/{scan_id}/export", "/api/"):
        assert path in spec, path
    assert any(getattr(r, "path", None) == "/ws/scan/{scan_id}" for r in compat.router.routes)
