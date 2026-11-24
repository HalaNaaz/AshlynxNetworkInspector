import concurrent.futures
from fastapi.testclient import TestClient
from backend.app.main import app


def test_concurrent_api_requests_do_not_block_health_endpoint(client: TestClient):
    """Verifies that synchronous endpoints offloaded to threadpool workers do not block health checks."""
    endpoints = [
        "/api/network/interfaces",
        "/api/reports/sources",
        "/api/capture/status",
        "/api/scanner/history",
        "/api/discovery/history",
        "/api/health",
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(client.get, ep) for ep in endpoints]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    for resp in results:
        assert resp.status_code == 200
        assert resp.json()["success"] is True
