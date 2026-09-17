# Route matrix

`POST /api/scans` and `POST /api/bulk-scans` share `routers.scans.run_scan_engine` (nmap_service / vuln_service / network_service). Legacy `/api/scheduled-scans` runs use the same job.
