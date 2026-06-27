import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt

from src.shared import config


def hash_password(password):
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return f"pbkdf2_sha256${base64.b64encode(salt).decode()}${base64.b64encode(derived).decode()}"


def verify_password(password, password_hash):
    try:
        algorithm, salt_b64, hash_b64 = password_hash.split("$")
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    salt = base64.b64decode(salt_b64.encode())
    expected = base64.b64decode(hash_b64.encode())
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return hmac.compare_digest(actual, expected)


def create_token(user):
    expires_at = datetime.now(timezone.utc) + timedelta(hours=12)
    payload = {
        "userId": user["userId"],
        "tenantId": user["tenantId"],
        "storeId": user.get("storeId") or "",
        "role": user["role"],
        "email": user["email"],
        "name": user.get("name", ""),
        "exp": expires_at,
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


def decode_token(token):
    return jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])


def get_bearer_token(headers):
    if not headers:
        return None
    authorization = headers.get("authorization") or headers.get("Authorization")
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]
