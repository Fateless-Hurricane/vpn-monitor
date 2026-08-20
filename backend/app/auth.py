import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123456")
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", secrets.token_hex(32))

# In-memory active tokens store: token -> {"username": str, "expires_at": float}
_ACTIVE_TOKENS: dict[str, dict] = {}
TOKEN_TTL_SECONDS = 86400 * 7  # 7 days

security_scheme = HTTPBearer(auto_error=False)


def verify_password(plain_password: str, expected_password: str) -> bool:
    """Constant-time comparison of passwords."""
    return hmac.compare_digest(
        plain_password.encode("utf-8"),
        expected_password.encode("utf-8"),
    )


def create_admin_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    _ACTIVE_TOKENS[token] = {
        "username": username,
        "expires_at": time.time() + TOKEN_TTL_SECONDS,
    }
    return token


def validate_admin_token(token: str) -> Optional[str]:
    if not token:
        return None
    session = _ACTIVE_TOKENS.get(token)
    if not session:
        return None
    if time.time() > session["expires_at"]:
        _ACTIVE_TOKENS.pop(token, None)
        return None
    return session["username"]


def revoke_admin_token(token: str) -> None:
    _ACTIVE_TOKENS.pop(token, None)


def get_current_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> str:
    """Dependency that requires valid Admin Bearer token."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username = validate_admin_token(credentials.credentials)
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


def get_optional_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> Optional[str]:
    """Dependency that checks if user is logged in as admin without throwing 401."""
    if not credentials or not credentials.credentials:
        return None
    return validate_admin_token(credentials.credentials)
