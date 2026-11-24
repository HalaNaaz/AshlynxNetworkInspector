import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import Settings


def test_cors_preflight_allowed_origin(client: TestClient):
    """Preflight OPTIONS request from allowed origin returns correct CORS headers."""
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type,Authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert response.headers.get("access-control-allow-credentials") == "true"
    allow_methods = response.headers.get("access-control-allow-methods", "")
    assert "GET" in allow_methods
    assert "OPTIONS" in allow_methods


def test_cors_preflight_disallowed_origin(client: TestClient):
    """Preflight OPTIONS request from an unauthorized origin is rejected/has no allow-origin."""
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://evil-attacker.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") is None


def test_cors_wildcard_rejected_by_config():
    """Settings validator must forbid '*' in cors_origins when credentials are enabled."""
    with pytest.raises(ValueError, match="Wildcard '\\*' origin is forbidden"):
        Settings(cors_origins=["*"])

    with pytest.raises(ValueError, match="Wildcard '\\*' origin is forbidden"):
        Settings(cors_origins="http://localhost:3000,*")
