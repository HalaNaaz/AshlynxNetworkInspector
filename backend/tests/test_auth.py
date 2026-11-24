import pytest
from fastapi.testclient import TestClient
from backend.app.core.security import get_active_token, get_token_file_path, reset_active_token
from backend.tests.conftest import TEST_AUTH_TOKEN


def test_public_health_endpoint_accessible_unauthenticated(unauth_client: TestClient):
    """GET /api/health remains public and requires no authentication token."""
    response = unauth_client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_public_docs_accessible_unauthenticated(unauth_client: TestClient):
    """OpenAPI schema and docs remain accessible without token."""
    response = unauth_client.get("/openapi.json")
    assert response.status_code == 200


@pytest.mark.parametrize(
    "method,endpoint,payload",
    [
        ("post", "/api/capture/start", {"interface_name": "eth0"}),
        ("post", "/api/capture/stop", None),
        ("post", "/api/capture/sessions/dummy/clear", None),
        ("post", "/api/scanner/scan", {"target": "127.0.0.1", "ports": [80]}),
        ("post", "/api/scanner/udp/scan", {"target": "127.0.0.1", "ports": [53]}),
        ("post", "/api/discovery/scan", {"cidr": "192.168.1.0/24"}),
        ("post", "/api/reports/generate", {"report_format": "json"}),
        ("delete", "/api/reports/dummy-id", None),
        ("patch", "/api/security/events/dummy-id/status", {"new_status": "ACKNOWLEDGED", "analyst_callsign": "analyst"}),
        ("post", "/api/security/events/dummy-id/notes", {"author": "analyst", "note": "Investigation note"}),
        ("patch", "/api/security/rules/rule-001", {"enabled": True}),
    ],
)
def test_administrative_endpoints_reject_missing_token(
    unauth_client: TestClient, method: str, endpoint: str, payload: dict
):
    """Protected endpoints reject requests without Authorization Bearer token with 401."""
    client_method = getattr(unauth_client, method)
    kwargs = {"json": payload} if payload is not None else {}
    response = client_method(endpoint, **kwargs)
    assert response.status_code == 401, f"Endpoint {endpoint} did not return 401 when unauthenticated"
    assert "WWW-Authenticate" in response.headers
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "method,endpoint,payload",
    [
        ("post", "/api/capture/start", {"interface_name": "eth0"}),
        ("post", "/api/scanner/scan", {"target": "127.0.0.1", "ports": [80]}),
        ("post", "/api/discovery/scan", {"cidr": "192.168.1.0/24"}),
    ],
)
def test_administrative_endpoints_reject_invalid_token(
    unauth_client: TestClient, method: str, endpoint: str, payload: dict
):
    """Protected endpoints reject requests with wrong token with 401."""
    client_method = getattr(unauth_client, method)
    kwargs = {
        "json": payload,
        "headers": {"Authorization": "Bearer completely-invalid-secret-token"},
    }
    response = client_method(endpoint, **kwargs)
    assert response.status_code == 401
    assert "Invalid API token" in response.json().get("detail", "")


def test_administrative_endpoints_accept_valid_token(client: TestClient):
    """Protected endpoints accept requests with valid token (validates past auth layer)."""
    # /api/scanner/scan with localhost target passes auth layer
    response = client.post(
        "/api/scanner/scan",
        json={"target": "127.0.0.1", "ports": [65534], "scan_speed": "INSANE", "timeout_ms": 100},
    )
    # The request must reach the service logic (200 OK or business logic response, not 401)
    assert response.status_code != 401


def test_token_file_resolution_and_generation(tmp_path, monkeypatch):
    """Verifies cryptographic token generation when no token is configured."""
    from backend.app.core import security, config

    reset_active_token()
    monkeypatch.setattr(config.settings, "api_token", None)
    monkeypatch.setattr(security, "get_token_file_path", lambda: tmp_path / ".ani_token")

    token = security.get_active_token()
    assert len(token) >= 32
    assert (tmp_path / ".ani_token").is_file()
    assert (tmp_path / ".ani_token").read_text(encoding="utf-8").strip() == token

    # Subsequent call returns cached token
    assert security.get_active_token() == token
    reset_active_token()
