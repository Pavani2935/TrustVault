"""Document operations. Every function that touches a specific document starts with
`load_document()`, which is the only way to obtain a Document object for a caller."""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import date, datetime, timedelta, timezone

from flask import current_app
from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session

from .. import audit
from ..errors import ApiError, not_found
from ..models import AuditEvent, Blob, Document, DocumentVersion, Grant, User, new_id, utcnow
from ..security import crypto
from ..security.policy import Action, Decision, decide
from ..validation import ValidationError, clean_category, clean_text, clean_title, validate_upload

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _settings():
    return current_app.config["TV_SETTINGS"]


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# --- the authorisation gate ------------------------------------------------------------

def load_document(db: Session, actor: User, doc_id: str, action: Action) -> tuple[Document, Decision]:
    """Fetch a document *and* authorise `action` on it, or raise 404/403.

    Refusals are written to the audit trail and committed before the error is raised,
    so attempts are recorded even though the request fails.
    """
    document = grant = None
    if isinstance(doc_id, str) and _UUID_RE.match(doc_id):
        doc_id = str(uuid.UUID(doc_id))
        document = db.get(Document, doc_id)
        if document is not None:
            grant = db.execute(
                select(Grant).where(Grant.document_id == document.id, Grant.user_id == actor.id)
            ).scalar_one_or_none()
    decision = decide(actor, document, action, grant)
    if not decision.allowed:
        audit.record(db, action=f"document.{action.value}", outcome="denied", actor=actor,
                     document_id=str(doc_id)[:64], details={"reason": decision.reason})
        db.commit()
        if decision.http_status == 404:
            raise not_found()
        raise ApiError(403, "forbidden", "Your access to this document does not allow that.")
    return document, decision


# --- serialisation ---------------------------------------------------------------------

def version_json(v: DocumentVersion) -> dict:
    return {
        "version": v.version_no, "filename": v.original_filename, "content_type": v.content_type,
        "size_bytes": v.size_bytes, "sha256": v.sha256, "created_at": iso(v.created_at),
        "uploaded_by": {"id": v.uploader.id, "username": v.uploader.username, "display_name": v.uploader.display_name},
    }


def document_json(doc: Document, permission: str, *, with_versions: bool = False) -> dict:
    latest = doc.versions[-1] if doc.versions else None
    data = {
        "id": doc.id, "title": doc.title, "category": doc.category,
        "owner": {"id": doc.owner.id, "username": doc.owner.username, "display_name": doc.owner.display_name},
        "my_permission": permission,
        "created_at": iso(doc.created_at), "updated_at": iso(doc.updated_at),
        "deleted_at": iso(doc.deleted_at),
        "latest_version": version_json(latest) if latest else None,
    }
    if with_versions:
        data["versions"] = [version_json(v) for v in reversed(doc.versions)]
    return data


# --- search / list ---------------------------------------------------------------------

def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _parse_date(value: str | None, field: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be a date (YYYY-MM-DD)", field) from exc


def accessible_filter(actor: User):
    """SQL condition for 'documents this person may see in lists'. Mirrors policy.decide()."""
    granted = exists().where(and_(Grant.document_id == Document.id, Grant.user_id == actor.id))
    return and_(Document.deleted_at.is_(None), or_(Document.owner_id == actor.id, granted))


def search(db: Session, actor: User, args) -> dict:
    stmt = select(Document).join(User, User.id == Document.owner_id).where(accessible_filter(actor))
    q = (args.get("q") or "").strip()[:100]
    if q:
        pattern = f"%{_escape_like(q.lower())}%"
        name_match = exists().where(and_(DocumentVersion.document_id == Document.id,
                                         func.lower(DocumentVersion.original_filename).like(pattern, escape="\\")))
        stmt = stmt.where(or_(func.lower(Document.title).like(pattern, escape="\\"), name_match))
    owner = (args.get("owner") or "").strip()[:64]
    if owner:
        pattern = f"%{_escape_like(owner.lower())}%"
        stmt = stmt.where(or_(func.lower(User.username).like(pattern, escape="\\"),
                              func.lower(User.display_name).like(pattern, escape="\\")))
    category = (args.get("category") or "").strip()[:60]
    if category:
        stmt = stmt.where(Document.category == category)
    date_from = _parse_date(args.get("from"), "from")
    date_to = _parse_date(args.get("to"), "to")
    if date_from:
        stmt = stmt.where(Document.created_at >= datetime.combine(date_from, datetime.min.time(), timezone.utc))
    if date_to:
        stmt = stmt.where(Document.created_at < datetime.combine(date_to + timedelta(days=1), datetime.min.time(), timezone.utc))

    sort = args.get("sort") or "-created_at"
    sort_map = {"created_at": Document.created_at, "title": func.lower(Document.title), "category": Document.category}
    column = sort_map.get(sort.lstrip("-"))
    if column is None:
        raise ValidationError("sort must be one of created_at, title, category (prefix - for descending)", "sort")
    stmt = stmt.order_by(column.desc() if sort.startswith("-") else column.asc(), Document.id)

    try:
        limit = max(1, min(int(args.get("limit", 50)), 100))
        offset = max(0, int(args.get("offset", 0)))
    except ValueError as exc:
        raise ValidationError("limit and offset must be integers") from exc

    total = db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    docs = db.execute(stmt.limit(limit).offset(offset)).unique().scalars().all()
    grants = {}
    if docs:
        rows = db.execute(select(Grant.document_id, Grant.permission).where(
            Grant.user_id == actor.id, Grant.document_id.in_([d.id for d in docs]))).all()
        grants = dict(rows)
    items = [document_json(d, "owner" if d.owner_id == actor.id else grants[d.id]) for d in docs]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def categories(db: Session, actor: User) -> list[str]:
    # Only categories of documents this person can see: a global list would leak
    # the existence of e.g. a "Layoffs 2026" category to everyone.
    rows = db.execute(select(Document.category).where(accessible_filter(actor)).distinct().order_by(Document.category))
    return [r[0] for r in rows]


# --- create / version / edit -------------------------------------------------------------

def _store_version(db: Session, actor: User, doc: Document, version_no: int, filename: str, data: bytes) -> DocumentVersion:
    name, ftype = validate_upload(data, filename, _settings().max_upload_bytes)
    version_id = new_id()
    ciphertext, wrapped = crypto.encrypt_file(_settings().master_key, doc.id, version_id, data)
    blob = Blob(id=new_id(), ciphertext=ciphertext)
    db.add(blob)
    version = DocumentVersion(
        id=version_id, document_id=doc.id, version_no=version_no, original_filename=name,
        content_type=ftype.content_type, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
        wrapped_key=wrapped, key_id=crypto.key_id(_settings().master_key), blob_id=blob.id,
        uploaded_by=actor.id, created_at=utcnow(),
    )
    db.add(version)
    return version


def create_document(db: Session, actor: User, *, title, category, filename: str, data: bytes) -> Document:
    if actor.role != "owner":
        audit.record(db, action="document.create", outcome="denied", actor=actor,
                     details={"reason": f"role '{actor.role}' cannot upload documents"})
        db.commit()
        raise ApiError(403, "forbidden", "Only document owners can upload new documents.")
    try:
        title, category = clean_title(title), clean_category(category)
        now = utcnow()
        doc = Document(id=new_id(), owner_id=actor.id, title=title, category=category, created_at=now, updated_at=now)
        db.add(doc)
        db.flush()
        version = _store_version(db, actor, doc, 1, filename, data)
    except ValidationError as exc:
        db.rollback()
        audit.record(db, action="document.create", outcome="denied", actor=actor,
                     details={"reason": "validation failed", "message": str(exc), "filename": str(filename)[:150],
                              "bytes": len(data)})
        db.commit()
        raise
    audit.record(db, action="document.create", actor=actor, document_id=doc.id, details={
        "title": title, "category": category, "filename": version.original_filename,
        "content_type": version.content_type, "size_bytes": version.size_bytes, "sha256": version.sha256})
    db.commit()
    db.refresh(doc)
    return doc


def add_version(db: Session, actor: User, doc_id: str, *, filename: str, data: bytes) -> DocumentVersion:
    doc, _ = load_document(db, actor, doc_id, Action.UPLOAD_VERSION)
    next_no = (db.execute(select(func.max(DocumentVersion.version_no)).where(
        DocumentVersion.document_id == doc.id)).scalar_one() or 0) + 1
    try:
        version = _store_version(db, actor, doc, next_no, filename, data)
    except ValidationError as exc:
        db.rollback()
        audit.record(db, action="document.upload_version", outcome="denied", actor=actor, document_id=doc.id,
                     details={"reason": "validation failed", "message": str(exc), "filename": str(filename)[:150]})
        db.commit()
        raise
    doc.updated_at = utcnow()
    audit.record(db, action="document.upload_version", actor=actor, document_id=doc.id, details={
        "version": next_no, "filename": version.original_filename, "size_bytes": version.size_bytes,
        "sha256": version.sha256})
    db.commit()
    return version


def update_metadata(db: Session, actor: User, doc_id: str, body: dict) -> Document:
    doc, decision = load_document(db, actor, doc_id, Action.EDIT_METADATA)
    changes = {}
    if "title" in body:
        new = clean_title(body["title"])
        if new != doc.title:
            changes["title"] = {"from": doc.title, "to": new}
            doc.title = new
    if "category" in body:
        new = clean_category(body["category"])
        if new != doc.category:
            changes["category"] = {"from": doc.category, "to": new}
            doc.category = new
    if changes:
        doc.updated_at = utcnow()
        audit.record(db, action="document.edit_metadata", actor=actor, document_id=doc.id, details={"changes": changes})
    db.commit()
    return doc


# --- read --------------------------------------------------------------------------------

def view(db: Session, actor: User, doc_id: str) -> dict:
    doc, decision = load_document(db, actor, doc_id, Action.VIEW)
    audit.record(db, action="document.view", actor=actor, document_id=doc.id, details={"as": decision.permission})
    db.commit()
    return document_json(doc, decision.permission, with_versions=True)


def download(db: Session, actor: User, doc_id: str, version_no: str | None, *, method: str = "GET") -> tuple[bytes, DocumentVersion]:
    doc, decision = load_document(db, actor, doc_id, Action.DOWNLOAD)
    if not doc.versions:
        raise not_found()
    if version_no in (None, ""):
        version = doc.versions[-1]
    else:
        if not str(version_no).isdigit():
            raise ValidationError("version must be a positive integer", "version")
        version = next((v for v in doc.versions if v.version_no == int(version_no)), None)
        if version is None:
            raise not_found()
    blob = db.get(Blob, version.blob_id)
    try:
        if blob is None:
            raise crypto.DecryptionError("blob missing")
        plaintext = crypto.decrypt_file(_settings().master_key, doc.id, version.id, version.wrapped_key, blob.ciphertext)
        if hashlib.sha256(plaintext).hexdigest() != version.sha256:
            raise crypto.DecryptionError("sha256 mismatch")
    except crypto.DecryptionError as exc:
        audit.record(db, action="document.download", outcome="error", actor=actor, document_id=doc.id,
                     details={"version": version.version_no, "reason": str(exc)})
        db.commit()
        raise ApiError(500, "integrity_error", "The stored file failed its integrity check and was not served.")
    # The audit record is committed BEFORE any byte leaves the server.
    audit.record(db, action="document.download", actor=actor, document_id=doc.id, details={
        "version": version.version_no, "sha256": version.sha256, "as": decision.permission, "method": method})
    db.commit()
    return plaintext, version


# --- delete / restore / purge ------------------------------------------------------------

def delete(db: Session, actor: User, doc_id: str) -> None:
    doc, _ = load_document(db, actor, doc_id, Action.DELETE)
    doc.deleted_at = utcnow()
    doc.deleted_by = actor.id
    doc.updated_at = doc.deleted_at
    grant_count = db.execute(select(func.count()).select_from(Grant).where(Grant.document_id == doc.id)).scalar_one()
    audit.record(db, action="document.delete", actor=actor, document_id=doc.id, details={
        "title": doc.title, "mode": "trash", "dormant_grants": grant_count,
        "retention_days": _settings().trash_retention_days})
    db.commit()


def restore(db: Session, actor: User, doc_id: str) -> Document:
    doc, _ = load_document(db, actor, doc_id, Action.RESTORE)
    doc.deleted_at = None
    doc.deleted_by = None
    doc.updated_at = utcnow()
    audit.record(db, action="document.restore", actor=actor, document_id=doc.id, details={"title": doc.title})
    db.commit()
    return doc


def _purge(db: Session, doc: Document) -> dict:
    summary = {"title": doc.title, "category": doc.category, "owner_id": doc.owner_id,
               "versions": [{"version": v.version_no, "sha256": v.sha256} for v in doc.versions]}
    blob_ids = [v.blob_id for v in doc.versions]
    db.query(Grant).filter(Grant.document_id == doc.id).delete(synchronize_session=False)
    db.delete(doc)  # cascades to versions (and their wrapped keys: crypto-shredding)
    db.flush()
    if blob_ids:
        db.query(Blob).filter(Blob.id.in_(blob_ids)).delete(synchronize_session=False)
    return summary


def purge(db: Session, actor: User, doc_id: str) -> None:
    doc, _ = load_document(db, actor, doc_id, Action.PURGE)
    if _settings().demo_mode and doc.is_demo_seed:
        raise ApiError(403, "demo_protected", "Seeded demo documents cannot be purged on the shared demo. Upload your own to try purge.")
    doc_id = doc.id
    summary = _purge(db, doc)
    audit.record(db, action="document.purge", actor=actor, document_id=doc_id, details=summary)
    db.commit()


def purge_expired(db: Session, days: int) -> int:
    cutoff = utcnow() - timedelta(days=days)
    docs = db.execute(select(Document).where(Document.deleted_at.is_not(None), Document.deleted_at < cutoff)).unique().scalars().all()
    for doc in docs:
        doc_id = doc.id
        summary = _purge(db, doc)
        audit.record(db, action="document.purge", actor_label="system:retention", document_id=doc_id,
                     details=summary | {"reason": f"in trash longer than {days} days"})
    db.commit()
    return len(docs)


def trash(db: Session, actor: User) -> list[dict]:
    docs = db.execute(select(Document).where(Document.owner_id == actor.id, Document.deleted_at.is_not(None))
                      .order_by(Document.deleted_at.desc())).unique().scalars().all()
    retention = _settings().trash_retention_days
    out = []
    for d in docs:
        item = document_json(d, "owner")
        deleted = d.deleted_at if d.deleted_at.tzinfo else d.deleted_at.replace(tzinfo=timezone.utc)
        item["purge_after"] = iso(deleted + timedelta(days=retention))
        out.append(item)
    return out


# --- per-document activity (for the owner) -----------------------------------------------

def activity(db: Session, actor: User, doc_id: str, limit: int = 200) -> list[dict]:
    doc, _ = load_document(db, actor, doc_id, Action.VIEW_ACTIVITY)
    rows = db.execute(select(AuditEvent).where(AuditEvent.document_id == doc.id)
                      .order_by(AuditEvent.seq.desc()).limit(limit)).scalars().all()
    return [event_json(e) for e in rows]


def event_json(e: AuditEvent) -> dict:
    import json as _json
    return {
        "seq": e.seq, "at": e.occurred_at, "actor": {"id": e.actor_id, "username": e.actor_username, "role": e.actor_role},
        "action": e.action, "outcome": e.outcome, "document_id": e.document_id, "target_user_id": e.target_user_id,
        "ip": e.ip, "request_id": e.request_id, "details": _json.loads(e.details or "{}"), "entry_hash": e.entry_hash,
    }


def clean_reason(value) -> str:
    return clean_text(value, "reason", max_len=300)
