from __future__ import annotations

from flask import g, jsonify

from ..db import get_db
from ..services import auth as auth_service
from ..services.documents import iso
from ..services.sharing import directory
from . import bp, json_body, login_required, roles_required, settings


def _me_payload():
    return {
        "user": {"id": g.user.id, "username": g.user.username, "display_name": g.user.display_name,
                 "role": g.user.role, "must_change_password": g.user.must_change_password},
        "csrf_token": g.session.csrf_token,
        "session_expires_at": iso(g.session.expires_at),
        "demo_mode": settings().demo_mode,
    }


@bp.post("/auth/login")
def login():
    body = json_body({"username", "password"}, {"username", "password"})
    db = get_db()
    from ..security.sessions import end_session, resolve_session
    token, user = auth_service.login(db, body["username"], body["password"])
    if g.session_token:  # signing in again replaces, rather than adds to, this browser's session
        end_session(db, g.session_token)
        db.commit()
    g.session, g.user = resolve_session(db, token)
    resp = jsonify(_me_payload())
    s = settings()
    resp.set_cookie(s.session_cookie_name, token, httponly=True, secure=s.cookie_secure, samesite="Strict",
                    path="/", max_age=s.session_absolute_hours * 3600)
    return resp


@bp.post("/auth/logout")
@login_required
def logout():
    auth_service.logout(get_db(), g.user, g.session_token)
    resp = jsonify({"ok": True})
    s = settings()
    resp.delete_cookie(s.session_cookie_name, path="/", secure=s.cookie_secure, samesite="Strict", httponly=True)
    return resp


@bp.get("/auth/me")
@login_required
def me():
    return jsonify(_me_payload())


@bp.post("/auth/change-password")
@login_required
def change_password():
    body = json_body({"current_password", "new_password"}, {"current_password", "new_password"})
    auth_service.change_password(get_db(), g.user, g.session_token, body["current_password"], body["new_password"])
    return jsonify({"ok": True})


@bp.get("/users/directory")
@roles_required("owner")
def users_directory():
    """People an owner can share with. Admins do not need it: they have /admin/users."""
    return jsonify({"items": directory(get_db())})
