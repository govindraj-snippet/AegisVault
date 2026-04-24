from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time bcrypt comparison. Never short-circuits."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Returns a bcrypt hash of the raw password."""
    return pwd_context.hash(password)


def create_access_token(data: dict[str, Any]) -> str:
    """
    Creates a signed JWT.
    - Encodes a copy to avoid mutating the caller's dict.
    - Expiry is always enforced; no infinite tokens.
    """
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decodes and validates a JWT.
    Raises jwt.PyJWTError on any failure — callers must handle this.
    """
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])