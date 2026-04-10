"""
auth.py — Simple JWT-based authentication for the platform.
"""

import hashlib
import time
import json
import base64
import hmac
import os

SECRET_KEY = os.environ.get("PLATFORM_SECRET", "vulnplatform-dev-secret-2024")

# Mock user database (in production use a real DB + bcrypt)
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": hashlib.sha256(b"admin123").hexdigest(),
        "role": "admin",
    },
    "analyst": {
        "username": "analyst",
        "password": hashlib.sha256(b"analyst123").hexdigest(),
        "role": "analyst",
    },
}


def create_token(username: str) -> str:
    """Create a simple HS256-style JWT (simplified for prototype)."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": username, "exp": int(time.time()) + 86400}).encode()
    ).decode().rstrip("=")
    sig_input = f"{header}.{payload}"
    sig = hmac.new(SECRET_KEY.encode(), sig_input.encode(), hashlib.sha256).hexdigest()
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> dict:
    """Verify token and return payload. Raises ValueError if invalid."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")
        header, payload, sig = parts
        sig_input = f"{header}.{payload}"
        expected_sig = hmac.new(SECRET_KEY.encode(), sig_input.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Invalid signature")
        data = json.loads(base64.urlsafe_b64decode(payload + "=="))
        if data.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return data
    except Exception as e:
        raise ValueError(str(e))