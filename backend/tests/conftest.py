import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.config import settings

TEST_AUTH_TOKEN = "ani-test-admin-bearer-token-12345"

# Patch TestClient to automatically provide administrative Bearer token
# unless explicitly marked as unauthenticated.
_orig_testclient_request = TestClient.request


def _patched_request(self, method, url, *args, **kwargs):
    headers = kwargs.get("headers")
    if headers is None:
        headers = {}
    else:
        headers = dict(headers)
    kwargs["headers"] = headers

    if "Authorization" not in headers and not getattr(self, "_unauthenticated", False):
        headers["Authorization"] = f"Bearer {TEST_AUTH_TOKEN}"

    return _orig_testclient_request(self, method, url, *args, **kwargs)


TestClient.request = _patched_request


@pytest.fixture(autouse=True)
def configure_test_auth_env():
    settings.api_token = TEST_AUTH_TOKEN
    settings.api_auth_enabled = True


@pytest.fixture(scope="session")
def client():
    """Provides a TestClient fixture with default administrative authorization."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def unauth_client():
    """Provides an unauthenticated TestClient fixture without authorization headers."""
    test_client = TestClient(app)
    test_client._unauthenticated = True
    yield test_client
