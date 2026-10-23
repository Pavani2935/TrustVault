"""Grants and access suggestions.

Only the document owner can change who has access (policy: MANAGE_GRANTS). An edit
grantee cannot re-share. Suggestions are advisory: they never create a grant. A grant
only exists after the owner confirms it, and both the suggestion and the decision are
written to the audit trail.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..errors import ApiError
from ..models import Document, Grant, User, utcnow
from ..security.policy import Action
from ..validation import ValidationError
from .documents import iso, load_document

MAX_SUGGESTIONS = 5


def grant_json(g: Grant) -> dict:
    return {
        "user": {"id": g.user.id, "username": g.user.username, "display_name": g.user.display_name,
                 "role": g.user.role, "is_active": g.user.is_active},
        "permission": g.permission, "source": g.source, "created_at": iso(g.created_at),
        "granted_by": {"id": g.granter.id, "username": g.granter.username},
    }


def list_grants(db: Session, actor: User, doc_id: str) -> list[dict]:
    doc, _ = load_document(db, actor, doc_id, Action.MANAGE_GRANTS)
    rows = db.execute(select(Grant).where(Grant.document_id == doc.id)).unique().scalars().all()
    return [grant_json(g) for g in sorted(rows, key=lambda g: g.user.username)]


def set_grant(db: Session, actor: User, doc_id: str, target_user_id: str, body: dict) -> dict:
    doc, _ = load_document(db, actor, doc_id, Action.MANAGE_GRANTS)
    permission = body.get("permission")
    source = body.get("source", "manual")
    if permission not in ("read", "edit"):
        raise ValidationError("permission must be 'read' or 'edit'", "permission")
    if source not in ("manual", "suggestion"):
        raise ValidationError("source must be 'manual' or 'suggestion'", "source")
    target = db.get(User, target_user_id) if isinstance(target_user_id, str) and len(target_user_id) <= 36 else None
    if target is None or not target.is_active:
        raise ApiError(404, "user_not_found", "No active user with that ID.")
    if target.id == doc.owner_id:
        raise ValidationError("the owner already has full access", "user_id")

    suggestion_context = None
    if source == "suggestion":
        # Do not let the client label an arbitrary grant as "suggested": check that the
        # engine really suggests this person right now, and record what it said.
        current = {s["user"]["id"]: s for s in _compute_suggestions(db, doc)}
        if target.id not in current:
            raise ValidationError("this person is not among the current suggestions", "source")
        suggestion_context = {"score": current[target.id]["score"], "reasons": current[target.id]["reasons"]}

    existing = db.execute(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == target.id)).scalar_one_or_none()
    previous = existing.permission if existing else None
    if existing is None:
        existing = Grant(document_id=doc.id, user_id=target.id, permission=permission,
                         granted_by=actor.id, source=source, created_at=utcnow())
        db.add(existing)
    elif existing.permission != permission:
        existing.permission = permission
        existing.granted_by = actor.id
        existing.source = source
        existing.created_at = utcnow()
    if previous != permission:
        details = {"permission": permission, "previous": previous, "source": source,
                   "target_username": target.username}
        if suggestion_context:
            details["suggestion"] = suggestion_context
        audit.record(db, action="grant.set", actor=actor, document_id=doc.id, target_user_id=target.id, details=details)
    db.commit()
    db.refresh(existing)
    return grant_json(existing)


def revoke_grant(db: Session, actor: User, doc_id: str, target_user_id: str) -> None:
    doc, _ = load_document(db, actor, doc_id, Action.MANAGE_GRANTS)
    existing = db.execute(select(Grant).where(Grant.document_id == doc.id, Grant.user_id == target_user_id)).scalar_one_or_none()
    if existing is None:
        raise ApiError(404, "grant_not_found", "That person has no grant on this document.")
    username, permission = existing.user.username, existing.permission
    db.delete(existing)
    # Effective immediately: the next request from that person re-reads the grant table
    # and finds nothing. There are no cached decisions or pre-signed links to expire.
    audit.record(db, action="grant.revoke", actor=actor, document_id=doc.id, target_user_id=target_user_id,
                 details={"previous": permission, "target_username": username})
    db.commit()


# --- suggestions ----------------------------------------------------------------------------

def _compute_suggestions(db: Session, doc: Document) -> list[dict]:
    """Rule-based and fully explainable: people this owner has already trusted with
    similar documents. No document content or metadata leaves the system."""
    current = {g.user_id for g in db.execute(select(Grant).where(Grant.document_id == doc.id)).unique().scalars()}
    rows = db.execute(
        select(Grant.user_id, Grant.permission, Document.category)
        .join(Document, Document.id == Grant.document_id)
        .where(Document.owner_id == doc.owner_id, Document.id != doc.id, Document.deleted_at.is_(None))
    ).all()
    score: dict[str, int] = defaultdict(int)
    same_cat: dict[str, int] = defaultdict(int)
    other: dict[str, int] = defaultdict(int)
    for user_id, _perm, category in rows:
        if category == doc.category:
            score[user_id] += 3
            same_cat[user_id] += 1
        else:
            score[user_id] += 1
            other[user_id] += 1
    candidates = [uid for uid in score if uid not in current and uid != doc.owner_id]
    if not candidates:
        return []
    users = {u.id: u for u in db.execute(select(User).where(User.id.in_(candidates))).scalars()}
    out = []
    for uid in sorted(candidates, key=lambda u: (-score[u], users[u].username if u in users else "")):
        u = users.get(uid)
        if u is None or not u.is_active or u.role == "admin":
            continue
        reasons = []
        if same_cat[uid]:
            reasons.append(f"has access to {same_cat[uid]} of your other '{doc.category}' document(s)")
        if other[uid]:
            reasons.append(f"has access to {other[uid]} of your documents in other categories")
        out.append({"user": {"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role},
                    "suggested_permission": "read", "score": score[uid], "reasons": reasons})
        if len(out) >= MAX_SUGGESTIONS:
            break
    return out


def suggestions(db: Session, actor: User, doc_id: str) -> list[dict]:
    doc, _ = load_document(db, actor, doc_id, Action.SUGGEST_ACCESS)
    result = _compute_suggestions(db, doc)
    audit.record(db, action="suggestion.shown", actor=actor, document_id=doc.id, details={
        "engine": "rules-v1", "suggested": [{"user_id": s["user"]["id"], "username": s["user"]["username"],
                                              "score": s["score"]} for s in result]})
    db.commit()
    return result


def dismiss_suggestion(db: Session, actor: User, doc_id: str, target_user_id: str) -> None:
    doc, _ = load_document(db, actor, doc_id, Action.SUGGEST_ACCESS)
    current = {s["user"]["id"]: s for s in _compute_suggestions(db, doc)}
    if target_user_id not in current:
        raise ValidationError("this person is not among the current suggestions", "user_id")
    audit.record(db, action="suggestion.dismissed", actor=actor, document_id=doc.id, target_user_id=target_user_id,
                 details={"username": current[target_user_id]["user"]["username"], "score": current[target_user_id]["score"]})
    db.commit()


def directory(db: Session) -> list[dict]:
    users = db.execute(select(User).where(User.is_active.is_(True)).order_by(User.username)).scalars().all()
    return [{"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role} for u in users]
