"""JSON API, /api/v1. The browser UI uses exactly this API; there is no second,
less-guarded set of routes behind it."""
from __future__ import annotations

from functools import wraps
from urllib.parse import urlsplit

from flask import Blueprint, current_app, g, request

from ..db import get_db
from ..errors import ApiError
from ..security import sessions
from ..validation import ValidationError

bp = Blueprint("api", __name__, url_prefix="/api/v1")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Endpoints a user who must change their password may still call.
PASSWORD_CHANGE_ALLOWED = {"api.me", "api.logout", "api.change_password"}


def settings():
    return current_app.config["TV_SETTINGS"]


@bp.before_request
def _authenticate_and_check_csrf():
    g.user = None
    g.session = None
    g.session_token = request.cookies.get(settings().session_cookie_name)
    resolved = sessions.resolve_session(get_db(), g.session_token)
    if resolved:
        g.session, g.user = resolved

    if request.method in SAFE_METHODS:
        return None
    # 1. Origin check: browsers always send Origin on cross-site POST/PUT/DELETE.
    origin = request.headers.get("Origin")
    if origin is not None:
        expected = f"{request.scheme}://{request.host}"
        parts = urlsplit(origin)
        if f"{parts.scheme}://{parts.netloc}" != expected:
            raise ApiError(403, "bad_origin", "Cross-origin request refused.")
    # 2. Login has no session yet: insist on a JSON body, which a cross-site HTML form cannot send.
    if request.endpoint == "api.login":
        if not request.is_json:
            raise ApiError(415, "unsupported_media_type", "Send JSON.")
        return None
    # 3. Everything else that changes state needs the per-session CSRF token in a header.
    if g.session is not None and not sessions.csrf_ok(g.session, request.headers.get("X-CSRF-Token")):
        raise ApiError(403, "csrf", "Missing or invalid CSRF token.")
    return None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            raise ApiError(401, "unauthenticated", "Sign in first.")
        if g.user.must_change_password and request.endpoint not in PASSWORD_CHANGE_ALLOWED:
            raise ApiError(403, "password_change_required", "Change your temporary password first.")
        return fn(*args, **kwargs)
    return wrapper


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user.role not in roles:
                from .. import audit
                db = get_db()
                audit.record(db, action="authz.role_denied", outcome="denied", actor=g.user,
                             details={"endpoint": request.endpoint, "path": request.path[:200], "required": list(roles)})
                db.commit()
                raise ApiError(403, "forbidden", "Your role does not allow this.")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def json_body(allowed: set[str], required: set[str] = frozenset()) -> dict:
    """Parse a JSON object and reject unknown fields (no mass assignment of e.g. owner_id)."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValidationError("request body must be a JSON object")
    unknown = set(body) - allowed
    if unknown:
        raise ValidationError(f"unknown field(s): {', '.join(sorted(unknown))}")
    missing = required - set(body)
    if missing:
        raise ValidationError(f"missing field(s): {', '.join(sorted(missing))}")
    return body


from . import routes_admin, routes_auth, routes_documents  # noqa: E402,F401
