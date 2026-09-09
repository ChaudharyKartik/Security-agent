"""
auth.py — password hashing + JWT-based authentication.

Single-role model: any valid, non-expired token grants full access. No
per-user permission tiers — this is an internal tool, not a multi-tenant
product (see database/models.py::User).

Applied once, at the router level, in main.py — not added to each route
individually. /,  /health, and /auth/login stay unauthenticated: / and
/health because Docker Compose's healthcheck (and the depends_on: condition:
service_healthy chain that gates the ui container on it) has no way to send
an auth header, and /auth/login because you obviously can't require a token
to get a token.
"""
import os
import logging
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from database.connection import get_db
from database import crud

logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not set in .env. Generate one with: "
        'python -c "import secrets; print(secrets.token_hex(32))"'
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))  # 8h

# tokenUrl only feeds FastAPI's auto-generated Swagger "Authorize" button —
# it doesn't change the real login route's path or behaviour.
# auto_error=False so a missing token raises our own 401 (with a clear
# detail message) instead of FastAPI's default, less specific one.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Malformed/foreign hash format — treat as a failed check, not a crash
        return False


def create_access_token(username: str) -> str:
    expire  = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> str:
    """
    FastAPI dependency — validates the Authorization: Bearer token and
    returns the username. Attached once, router-wide, in main.py.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise unauthorized
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise unauthorized
    except JWTError:
        raise unauthorized

    if not crud.get_user_by_username(db, username):
        # Token is validly signed but the user no longer exists — treat as
        # unauthenticated rather than trusting a stale/deleted identity.
        raise unauthorized
    return username


def ensure_initial_user(db: Session) -> None:
    """
    Called once at startup. If no users exist yet, create one from
    ADMIN_USERNAME/ADMIN_PASSWORD in .env — keeps setup consistent with the
    rest of the project (copy .env.example, fill in values, start) instead
    of needing a separate seed script or manual DB insert.
    """
    if crud.count_users(db) > 0:
        return

    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    if not username or not password:
        logger.warning(
            "[AUTH] No users exist and ADMIN_USERNAME/ADMIN_PASSWORD are not "
            "set in .env — no one will be able to log in until a user is "
            "created manually."
        )
        return

    crud.create_user(db, username, hash_password(password))
    logger.info(f"[AUTH] Initial user created: {username}")
