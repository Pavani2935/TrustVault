"""Password hashing (Argon2id) and password policy."""
from __future__ import annotations

import os

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Argon2id with the library's recommended parameters. The test suite creates thousands of
# accounts, so it opts into cheap parameters via TV_FAST_PASSWORD_HASHING=1; never in production.
if os.environ.get("TV_FAST_PASSWORD_HASHING") == "1" and os.environ.get("TV_ENV") != "production":
    _hasher = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
else:
    _hasher = PasswordHasher()

# Verifying against this when the username does not exist keeps response timing
# the same for "no such user" and "wrong password" (no username enumeration by timing).
_DUMMY_HASH = _hasher.hash("tv-dummy-password-for-timing-equalisation")

_COMMON = {
    "password1234", "123456789012", "qwertyuiop12", "trustvault123", "letmein12345",
    "welcome12345", "administrator", "passw0rd1234", "changeme1234",
}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str, username: str) -> list[str]:
    problems = []
    if not isinstance(password, str) or len(password) < 12:
        problems.append("must be at least 12 characters")
    elif len(password) > 128:
        problems.append("must be at most 128 characters")
    else:
        if password.lower() in _COMMON:
            problems.append("is too common")
        if username and username.lower() in password.lower():
            problems.append("must not contain the username")
        classes = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                       any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
        if classes < 3:
            problems.append("must mix at least three of: lower case, upper case, digits, symbols")
    return problems
