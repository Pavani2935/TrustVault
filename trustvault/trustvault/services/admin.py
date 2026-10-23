"""Administrator operations: identities, ownership transfer, audit trail, activity.

Administrators manage *who people are*; they do not read documents. Nothing here
returns file contents or grants an administrator access to one.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from flask import current_app
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..errors import ApiError, not_found
from ..models import ROLES, AuditEvent, Document, Grant, User, utcnow
from ..security import passwords, sessions
from ..validation import ValidationError, clean_text
from .documents import event_json, iso

USERNAME_RE = r"[a-z0-9][a-z0-9._-]{2,31}"


def _settings():
    return current_app.config["TV_SETTINGS"]


def user_json(db: Session, u: User) -> dict:
    owned = db.execute(select(func.count()).select_from(Document).where(Document.owner_id == u.id)).scalar_one()
    return {
        "id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role,
        "is_active": u.is_active, "must_change_password": u.must_change_password,
        "is_demo_account": u.is_demo_account, "created_at": iso(u.created_at), "updated_at": iso(u.updated_at),
        "active_sessions": sessions.active_session_count(db, u.id), "owned_documents": owned,
    }


def list_users(db: Session) -> list[dict]:
    return [user_json(db, u) for u in db.execute(select(User).order_by(User.username)).scalars()]


def _get_user(db: Session, user_id: str) -> User:
    u = db.get(User, user_id) if isinstance(user_id, str) and len(user_id) <= 36 else None
    if u is None:
        raise not_found()
    return u


def _demo_guard(target: User) -> None:
    if _settings().demo_mode and target.is_demo_account:
        raise ApiError(403, "demo_protected",
                       "Shared demo accounts cannot be changed on the demo deployment. Create a new account to try this.")


def create_user(db: Session, admin: User, body: dict) -> dict:
    username = body.get("username", "")
    if not isinstance(username, str) or not re.fullmatch(USERNAME_RE, username.strip().lower()):
        raise ValidationError("username: 3-32 characters, lower-case letters, digits, '.', '_' or '-'", "username")
    username = username.strip().lower()
    display_name = clean_text(body.get("display_name", username), "display_name", max_len=80)
    role = body.get("role")
    if role not in ROLES:
        raise ValidationError("role must be admin, owner or viewer", "role")
    password = body.get("password")
    problems = passwords.password_problems(password, username)
    if problems:
        raise ValidationError("Password " + "; ".join(problems), "password")
    user = User(username=username, display_name=display_name, role=role,
                password_hash=passwords.hash_password(password), must_change_password=True)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "conflict", "That username is already taken.", "username")
    audit.record(db, action="user.create", actor=admin, target_user_id=user.id,
                 details={"username": username, "role": role})
    db.commit()
    return user_json(db, user)


def update_user(db: Session, admin: User, user_id: str, body: dict) -> dict:
    target = _get_user(db, user_id)
    changes = {}
    end_sessions = False
    if "display_name" in body:
        new = clean_text(body["display_name"], "display_name", max_len=80)
        if new != target.display_name:
            changes["display_name"] = {"from": target.display_name, "to": new}
            target.display_name = new
    if "role" in body and body["role"] != target.role:
        role = body["role"]
        if role not in ROLES:
            raise ValidationError("role must be admin, owner or viewer", "role")
        _demo_guard(target)
        if target.id == admin.id:
            raise ApiError(409, "conflict", "You cannot change your own role.")
        if target.role == "owner":
            owned = db.execute(select(func.count()).select_from(Document).where(Document.owner_id == target.id)).scalar_one()
            if owned:
                raise ApiError(409, "owns_documents",
                               f"{target.username} owns {owned} document(s). Transfer them before changing the role.")
        changes["role"] = {"from": target.role, "to": role}
        target.role = role
        end_sessions = True
    if "is_active" in body and body["is_active"] != target.is_active:
        if not isinstance(body["is_active"], bool):
            raise ValidationError("is_active must be true or false", "is_active")
        _demo_guard(target)
        if target.id == admin.id:
            raise ApiError(409, "conflict", "You cannot deactivate yourself.")
        changes["is_active"] = {"from": target.is_active, "to": body["is_active"]}
        target.is_active = body["is_active"]
        end_sessions = end_sessions or not target.is_active
    if not changes:
        return user_json(db, target)
    target.updated_at = utcnow()
    ended = sessions.end_all_sessions(db, target.id) if end_sessions else 0
    action = "user.deactivate" if changes.get("is_active", {}).get("to") is False else (
        "user.activate" if changes.get("is_active", {}).get("to") is True else "user.update")
    if "role" in changes:
        action = "user.role_change" if action == "user.update" else action
    audit.record(db, action=action, actor=admin, target_user_id=target.id,
                 details={"username": target.username, "changes": changes, "sessions_ended": ended})
    db.commit()
    return user_json(db, target)


def reset_password(db: Session, admin: User, user_id: str, body: dict) -> dict:
    target = _get_user(db, user_id)
    _demo_guard(target)
    password = body.get("password")
    problems = passwords.password_problems(password, target.username)
    if problems:
        raise ValidationError("Password " + "; ".join(problems), "password")
    target.password_hash = passwords.hash_password(password)
    target.must_change_password = True
    target.updated_at = utcnow()
    ended = sessions.end_all_sessions(db, target.id)
    audit.record(db, action="user.reset_password", actor=admin, target_user_id=target.id,
                 details={"username": target.username, "sessions_ended": ended})
    db.commit()
    return user_json(db, target)


def revoke_sessions(db: Session, admin: User, user_id: str) -> dict:
    target = _get_user(db, user_id)
    ended = sessions.end_all_sessions(db, target.id)
    audit.record(db, action="user.revoke_sessions", actor=admin, target_user_id=target.id,
                 details={"username": target.username, "sessions_ended": ended})
    db.commit()
    return {"sessions_ended": ended}


def list_documents(db: Session) -> list[dict]:
    """Metadata only, for offboarding and oversight. No versions, no file names, no content."""
    docs = db.execute(select(Document).order_by(Document.created_at.desc())).unique().scalars().all()
    counts = dict(db.execute(select(Grant.document_id, func.count()).group_by(Grant.document_id)).all())
    return [{
        "id": d.id, "title": d.title, "category": d.category,
        "owner": {"id": d.owner.id, "username": d.owner.username, "is_active": d.owner.is_active},
        "grant_count": counts.get(d.id, 0), "created_at": iso(d.created_at), "deleted_at": iso(d.deleted_at),
    } for d in docs]


def transfer_ownership(db: Session, admin: User, doc_id: str, body: dict) -> dict:
    doc = db.get(Document, doc_id) if isinstance(doc_id, str) and len(doc_id) <= 36 else None
    if doc is None:
        raise not_found()
    if _settings().demo_mode and doc.is_demo_seed:
        raise ApiError(403, "demo_protected",
                       "Seeded demo documents cannot be transferred on the shared demo. Upload your own to try this.")
    new_owner = _get_user(db, body.get("new_owner_id", ""))
    if not new_owner.is_active or new_owner.role != "owner":
        raise ValidationError("the new owner must be an active account with the owner role", "new_owner_id")
    if new_owner.id == doc.owner_id:
        raise ValidationError("that person already owns the document", "new_owner_id")
    reason = clean_text(body.get("reason"), "reason", max_len=300)
    old_owner_id = doc.owner_id
    # The new owner supersedes any grant they held; the previous owner keeps nothing.
    db.query(Grant).filter(Grant.document_id == doc.id, Grant.user_id == new_owner.id).delete(synchronize_session=False)
    doc.owner_id = new_owner.id
    doc.updated_at = utcnow()
    audit.record(db, action="document.transfer_ownership", actor=admin, document_id=doc.id, target_user_id=new_owner.id,
                 details={"from_owner_id": old_owner_id, "to_owner_id": new_owner.id,
                          "to_username": new_owner.username, "title": doc.title, "reason": reason})
    db.commit()
    db.refresh(doc)
    return {"id": doc.id, "owner_id": doc.owner_id}


# --- audit trail ----------------------------------------------------------------------------

def query_audit(db: Session, args) -> dict:
    stmt = select(AuditEvent)
    if args.get("action"):
        stmt = stmt.where(AuditEvent.action.like(args["action"].replace("%", "").replace("_", "\\_")[:48] + "%", escape="\\"))
    if args.get("outcome") in ("success", "denied", "error"):
        stmt = stmt.where(AuditEvent.outcome == args["outcome"])
    if args.get("actor"):
        stmt = stmt.where(AuditEvent.actor_username == args["actor"].strip().lower()[:64])
    if args.get("document_id"):
        stmt = stmt.where(AuditEvent.document_id == args["document_id"][:64])
    if args.get("target_user_id"):
        stmt = stmt.where(AuditEvent.target_user_id == args["target_user_id"][:36])
    if args.get("from"):
        stmt = stmt.where(AuditEvent.occurred_at >= args["from"][:10])
    if args.get("to"):
        stmt = stmt.where(AuditEvent.occurred_at < args["to"][:10] + "T99")
    try:
        limit = max(1, min(int(args.get("limit", 100)), 500))
        before = int(args["before_seq"]) if args.get("before_seq") else None
    except ValueError as exc:
        raise ValidationError("limit and before_seq must be integers") from exc
    if before:
        stmt = stmt.where(AuditEvent.seq < before)
    rows = db.execute(stmt.order_by(AuditEvent.seq.desc()).limit(limit)).scalars().all()
    return {"items": [event_json(e) for e in rows],
            "next_before_seq": rows[-1].seq if len(rows) == limit else None}


def verify_audit(db: Session, admin: User) -> dict:
    s = _settings()
    external = audit.read_anchor_file(s.audit_anchor_file) if s.audit_anchor_file else []
    report = audit.verify_chain(db, s.audit_key, external)
    audit.record(db, action="audit.verify", actor=admin, details={
        "valid": report["valid"], "events": report["events"], "head_seq": report["head_seq"],
        "problems": report["problems"][:5]})
    audit.checkpoint_now(db)
    db.commit()
    return report


# --- activity overview & alerts -----------------------------------------------------------

def overview(db: Session) -> dict:
    s = _settings()
    now = datetime.now(timezone.utc)
    hour_ago = audit.timestamp(now - timedelta(hours=1))
    day_ago = audit.timestamp(now - timedelta(hours=24))
    week_ago = audit.timestamp(now - timedelta(days=7))
    recent = db.execute(select(AuditEvent).where(AuditEvent.occurred_at >= day_ago).order_by(AuditEvent.seq)).scalars().all()
    t = s.alert_thresholds
    alerts: list[dict] = []

    def add(severity, kind, message, events):
        alerts.append({"severity": severity, "kind": kind, "message": message, "count": len(events),
                       "first_seen": events[0].occurred_at, "last_seen": events[-1].occurred_at,
                       "seqs": [e.seq for e in events[-20:]]})

    last_hour = [e for e in recent if e.occurred_at >= hour_ago]
    by = defaultdict(list)
    for e in last_hour:
        if e.outcome == "denied" and e.action.startswith("document."):
            by[("denied", e.actor_username)].append(e)
        if e.action == "auth.login" and e.outcome == "denied":
            by[("login_user", e.actor_username)].append(e)
            by[("login_ip", e.ip)].append(e)
        if e.action == "document.download" and e.outcome == "success":
            by[("download", e.actor_username)].append(e)
        if e.action.startswith("grant.") and e.outcome == "success":
            by[("grants", e.actor_username)].append(e)
    for (kind, who), events in by.items():
        if kind == "denied" and len(events) >= t["denied_per_hour"]:
            docs = len({e.document_id for e in events})
            add("high", "access_probing", f"{who} was refused {len(events)} document request(s) on {docs} document(s) in the last hour", events)
        elif kind == "login_user" and len(events) >= t["login_failures_per_hour"]:
            add("medium", "login_failures", f"{len(events)} failed sign-ins for account '{who}' in the last hour", events)
        elif kind == "login_ip" and len(events) >= t["login_failures_per_hour"] * 2:
            add("medium", "login_failures_ip", f"{len(events)} failed sign-ins from {who} in the last hour", events)
        elif kind == "download" and len(events) >= t["downloads_per_hour"]:
            add("high", "bulk_download", f"{who} downloaded {len(events)} file(s) in the last hour", events)
        elif kind == "grants" and len(events) >= t["grant_changes_per_hour"]:
            add("medium", "permission_churn", f"{who} made {len(events)} permission changes in the last hour", events)

    for e in recent:
        if e.action == "document.transfer_ownership":
            add("medium", "ownership_transfer", f"{e.actor_username} transferred ownership of a document", [e])
        elif e.action == "user.role_change" and '"to":"admin"' in e.details:
            add("high", "new_admin", f"{e.actor_username} gave the administrator role to an account", [e])
        elif e.action == "user.create" and '"role":"admin"' in e.details:
            add("high", "new_admin", f"{e.actor_username} created a new administrator account", [e])
        elif e.action == "document.download" and e.outcome == "error":
            add("high", "integrity_failure", "A stored file failed its integrity check", [e])
        elif e.action == "audit.verify" and '"valid":false' in e.details:
            add("critical", "audit_tampering", "Audit chain verification FAILED", [e])

    # Downloads by people who were deactivated shortly afterwards (classic leaver pattern).
    deactivated = [e for e in recent if e.action == "user.deactivate"]
    for d in deactivated:
        window_start = audit.timestamp(datetime.fromisoformat(d.occurred_at.replace("Z", "+00:00")) - timedelta(days=7))
        prior = db.execute(select(AuditEvent).where(
            AuditEvent.actor_id == d.target_user_id, AuditEvent.action == "document.download",
            AuditEvent.outcome == "success", AuditEvent.occurred_at >= window_start,
            AuditEvent.occurred_at <= d.occurred_at).order_by(AuditEvent.seq)).scalars().all()
        if prior:
            add("medium", "leaver_downloads", f"An account deactivated by {d.actor_username} downloaded {len(prior)} file(s) in the 7 days before", prior)

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: a["last_seen"], reverse=True)
    alerts.sort(key=lambda a: severity_rank[a["severity"]])

    counts = Counter((e.action, e.outcome) for e in recent)
    permission_changes = db.execute(select(AuditEvent).where(
        AuditEvent.occurred_at >= week_ago,
        AuditEvent.action.in_(["grant.set", "grant.revoke", "document.transfer_ownership"])
    ).order_by(AuditEvent.seq.desc()).limit(25)).scalars().all()
    totals = {
        "users": db.execute(select(func.count()).select_from(User)).scalar_one(),
        "active_users": db.execute(select(func.count()).select_from(User).where(User.is_active.is_(True))).scalar_one(),
        "documents": db.execute(select(func.count()).select_from(Document).where(Document.deleted_at.is_(None))).scalar_one(),
        "in_trash": db.execute(select(func.count()).select_from(Document).where(Document.deleted_at.is_not(None))).scalar_one(),
        "grants": db.execute(select(func.count()).select_from(Grant)).scalar_one(),
        "audit_events": db.execute(select(func.max(AuditEvent.seq))).scalar_one() or 0,
    }
    last_24h = {
        "downloads": counts[("document.download", "success")],
        "views": counts[("document.view", "success")],
        "uploads": counts[("document.create", "success")] + counts[("document.upload_version", "success")],
        "denied": sum(v for (a, o), v in counts.items() if o == "denied"),
        "permission_changes": counts[("grant.set", "success")] + counts[("grant.revoke", "success")],
        "failed_logins": counts[("auth.login", "denied")],
    }
    return {"totals": totals, "last_24h": last_24h, "alerts": alerts,
            "recent_permission_changes": [event_json(e) for e in permission_changes]}
