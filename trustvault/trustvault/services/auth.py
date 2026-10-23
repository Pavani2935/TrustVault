"""Login, logout and password changes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import current_app, request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..errors import ApiError
from ..models import User, utcnow
from ..security import passwords, sessions
from ..validation import ValidationError


def _settings():
    return current_app.config["TV_SETTINGS"]


def normalise_username(value) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value.strip().lower() if ch.isprintable())[:64]


def login(db: Session, username_raw, password) -> tuple[str, User]:
    s = _settings()
    username = normalise_username(username_raw)
    if not isinstance(password, str):
        password = ""
    ip = request.remote_addr
    since = audit.timestamp(datetime.now(timezone.utc) - timedelta(minutes=s.login_window_minutes))
    per_ip = audit.count_recent(db, action="auth.login", outcome="denied", ip=ip, since=since)
    per_user_ip = audit.count_recent(db, action="auth.login", outcome="denied", ip=ip, since=since,
                                     actor_username=username or "anonymous")
    if per_ip >= s.login_max_failures_per_ip or per_user_ip >= s.login_max_failures_per_user_ip:
        # Throttle per (account, IP) and per IP rather than locking the account, so an
        # attacker cannot lock a real person out just by guessing at their username.
        audit.record(db, action="auth.login", outcome="denied", actor_label=username or "anonymous",
                     details={"reason": "throttled", "failures_ip": per_ip, "failures_user_ip": per_user_ip})
        db.commit()
        raise ApiError(429, "too_many_attempts", f"Too many failed sign-ins. Try again in {s.login_window_minutes} minutes.")

    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none() if username else None
    ok = passwords.verify_password(user.password_hash if user else None, password[:256])
    if not ok or not user.is_active:
        reason = "unknown user" if user is None else ("account deactivated" if ok else "wrong password")
        audit.record(db, action="auth.login", outcome="denied", actor=user if user else None,
                     actor_label=username or "anonymous", details={"reason": reason})
        db.commit()
        raise ApiError(401, "invalid_credentials", "Sign-in failed. Check your username and password.")
    token, _row = sessions.create_session(db, user)
    audit.record(db, action="auth.login", actor=user, details={"user_agent": (request.headers.get("User-Agent") or "")[:120]})
    db.commit()
    return token, user


def logout(db: Session, user: User, token: str) -> None:
    sessions.end_session(db, token)
    audit.record(db, action="auth.logout", actor=user)
    db.commit()


def change_password(db: Session, user: User, token: str, current, new) -> None:
    if _settings().demo_mode and user.is_demo_account:
        raise ApiError(403, "demo_protected", "Shared demo accounts cannot change their password.")
    if not isinstance(current, str) or not passwords.verify_password(user.password_hash, current):
        audit.record(db, action="auth.change_password", outcome="denied", actor=user, details={"reason": "current password wrong"})
        db.commit()
        raise ApiError(400, "invalid", "Current password is incorrect.", "current_password")
    problems = passwords.password_problems(new, user.username)
    if problems:
        raise ValidationError("New password " + "; ".join(problems), "new_password")
    if passwords.verify_password(user.password_hash, new):
        raise ValidationError("New password must differ from the current one", "new_password")
    user.password_hash = passwords.hash_password(new)
    user.must_change_password = False
    user.updated_at = utcnow()
    ended = sessions.end_all_sessions(db, user.id, except_token=token)
    audit.record(db, action="auth.change_password", actor=user, details={"other_sessions_ended": ended})
    db.commit()
