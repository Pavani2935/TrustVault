"""Server-side sessions, CSRF tokens and login throttling.

Why not Flask's default signed-cookie session: a signed cookie stays valid until it
expires no matter what happens on the server. Logging out, deactivating the person
or changing their role would not invalidate a copy of the cookie. Here the cookie is
an opaque random token and the server looks it up on every request, so deleting the
row ends the session immediately.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app, request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from ..models import Session, User


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_session(db: DbSession, user: User) -> tuple[str, Session]:
    settings = current_app.config["TV_SETTINGS"]
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    row = Session(
        token_hash=_hash(token), user_id=user.id, csrf_token=secrets.token_urlsafe(32),
        created_at=now, last_seen_at=now, expires_at=now + timedelta(hours=settings.session_absolute_hours),
        ip=(request.remote_addr or "")[:64], user_agent=(request.headers.get("User-Agent") or "")[:200],
    )
    db.add(row)
    return token, row


def resolve_session(db: DbSession, token: str | None) -> tuple[Session, User] | None:
    """Return (session, user) only if the session exists, is unexpired and the user is active."""
    if not token or len(token) > 100:
        return None
    row = db.get(Session, _hash(token))
    if row is None:
        return None
    settings = current_app.config["TV_SETTINGS"]
    now = datetime.now(timezone.utc)
    idle_limit = _aware(row.last_seen_at) + timedelta(minutes=settings.session_idle_minutes)
    if now > _aware(row.expires_at) or now > idle_limit:
        db.delete(row)
        db.commit()
        return None
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        db.delete(row)
        db.commit()
        return None
    if (now - _aware(row.last_seen_at)).total_seconds() > 30:
        row.last_seen_at = now
        db.commit()
    return row, user


def end_session(db: DbSession, token: str | None) -> None:
    if token:
        db.execute(delete(Session).where(Session.token_hash == _hash(token)))


def end_all_sessions(db: DbSession, user_id: str, *, except_token: str | None = None) -> int:
    stmt = delete(Session).where(Session.user_id == user_id)
    if except_token:
        stmt = stmt.where(Session.token_hash != _hash(except_token))
    return db.execute(stmt).rowcount or 0


def active_session_count(db: DbSession, user_id: str) -> int:
    return len(db.execute(select(Session.token_hash).where(Session.user_id == user_id)).all())


def csrf_ok(session_row: Session, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(session_row.csrf_token, supplied)
