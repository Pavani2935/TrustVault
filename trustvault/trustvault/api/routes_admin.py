from __future__ import annotations

from flask import g, jsonify, request

from ..db import get_db
from ..services import admin
from . import bp, json_body, roles_required


@bp.get("/admin/overview")
@roles_required("admin")
def admin_overview():
    return jsonify(admin.overview(get_db()))


@bp.get("/admin/users")
@roles_required("admin")
def admin_list_users():
    return jsonify({"items": admin.list_users(get_db())})


@bp.post("/admin/users")
@roles_required("admin")
def admin_create_user():
    body = json_body({"username", "display_name", "role", "password"}, {"username", "role", "password"})
    return jsonify(admin.create_user(get_db(), g.user, body)), 201


@bp.patch("/admin/users/<user_id>")
@roles_required("admin")
def admin_update_user(user_id):
    body = json_body({"display_name", "role", "is_active"})
    return jsonify(admin.update_user(get_db(), g.user, user_id, body))


@bp.post("/admin/users/<user_id>/reset-password")
@roles_required("admin")
def admin_reset_password(user_id):
    body = json_body({"password"}, {"password"})
    return jsonify(admin.reset_password(get_db(), g.user, user_id, body))


@bp.post("/admin/users/<user_id>/revoke-sessions")
@roles_required("admin")
def admin_revoke_sessions(user_id):
    return jsonify(admin.revoke_sessions(get_db(), g.user, user_id))


@bp.get("/admin/documents")
@roles_required("admin")
def admin_documents():
    return jsonify({"items": admin.list_documents(get_db())})


@bp.post("/admin/documents/<doc_id>/transfer")
@roles_required("admin")
def admin_transfer(doc_id):
    body = json_body({"new_owner_id", "reason"}, {"new_owner_id", "reason"})
    return jsonify(admin.transfer_ownership(get_db(), g.user, doc_id, body))


@bp.get("/admin/audit")
@roles_required("admin")
def admin_audit():
    return jsonify(admin.query_audit(get_db(), request.args))


@bp.post("/admin/audit/verify")
@roles_required("admin")
def admin_audit_verify():
    return jsonify(admin.verify_audit(get_db(), g.user))
