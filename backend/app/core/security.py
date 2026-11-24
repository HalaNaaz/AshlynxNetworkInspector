import hmac
import secrets
from pathlib import Path
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from backend.app.core.config import settings
from backend.app.core.logging import logger

security_scheme = HTTPBearer(auto_error=False)

_cached_token: Optional[str] = None


def get_token_file_path() -> Path:
    """Returns absolute path to the local .ani_token administrative secret file."""
    data_dir = Path(__file__).resolve().parent.parent.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / ".ani_token"


def get_active_token() -> str:
    """
    Retrieves or generates the active administrative API token.
    Precedence:
    1. settings.api_token (from ANI_API_TOKEN env var)
    2. Cached token in memory
    3. Token persisted in backend/data/.ani_token
    4. Auto-generated cryptographically secure 32-byte urlsafe token persisted to .ani_token
    """
    global _cached_token

    if settings.api_token:
        return settings.api_token

    if _cached_token:
        return _cached_token

    token_path = get_token_file_path()
    if token_path.is_file():
        try:
            token_val = token_path.read_text(encoding="utf-8").strip()
            if token_val:
                _cached_token = token_val
                return _cached_token
        except Exception as e:
            logger.warning("Could not read token from %s: %s", token_path, e)

    # Generate new token
    new_token = secrets.token_urlsafe(32)
    try:
        token_path.write_text(new_token, encoding="utf-8")
        try:
            token_path.chmod(0o600)
        except Exception:
            pass
        logger.info("Generated new administrative API token at %s", token_path)
    except Exception as e:
        logger.error("Could not write token file %s: %s", token_path, e)

    _cached_token = new_token
    return _cached_token


def reset_active_token() -> None:
    """Resets cached token (useful for test isolation)."""
    global _cached_token
    _cached_token = None


def init_api_token() -> str:
    """Initializes and logs the API token status at application boot."""
    token = get_active_token()
    token_path = get_token_file_path()
    logger.info("API Authentication enabled: administrative token registered (token file: %s)", token_path)
    return token


async def verify_api_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> str:
    """
    FastAPI dependency enforcing administrative Bearer token authentication.
    Prevents unauthenticated control-plane invocations (scans, captures, reports, rule mutations).
    """
    if not settings.api_auth_enabled:
        return "auth-disabled"

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expected_token = get_active_token()
    if not hmac.compare_digest(credentials.credentials, expected_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
