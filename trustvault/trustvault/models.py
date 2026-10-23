"""Database schema.

Design notes
- IDs are random UUIDs. Security never depends on them being secret: every
  request is authorised against the grant table regardless of how the ID was obtained.
- `audit_events` has no foreign keys on purpose. Evidence must outlive the users
  and documents it describes (a purged document is still in the audit trail).
- File bytes live only in `blobs`, encrypted. There is no filesystem path and no
  public URL for any file.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, LargeBinary,
    String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


ROLES = ("admin", "owner", "viewer")
PERMISSIONS = ("read", "edit")


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(80), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(10), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_demo_account: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    __table_args__ = (CheckConstraint("role IN ('admin','owner','viewer')", name="ck_users_role"),)


class Session(Base):
    """Server-side sessions. The cookie carries a random token; only its SHA-256 is stored.

    Deleting a row ends that session on the very next request, which is what makes
    deactivation, role changes and password resets take effect immediately.
    """
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(200))


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    deleted_by: Mapped[str | None] = mapped_column(String(36))
    is_demo_seed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    owner: Mapped[User] = relationship(lazy="joined")
    versions: Mapped[list["DocumentVersion"]] = relationship(
        back_populates="document", order_by="DocumentVersion.version_no", cascade="all, delete-orphan")


class Blob(Base):
    """AES-256-GCM ciphertext (nonce || ciphertext+tag). Nothing else can read it."""
    __tablename__ = "blobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class DocumentVersion(Base):
    __tablename__ = "document_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    version_no: Mapped[int] = mapped_column(Integer, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(160), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(String(16), nullable=False)
    blob_id: Mapped[str] = mapped_column(ForeignKey("blobs.id"), nullable=False, unique=True)
    uploaded_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    document: Mapped[Document] = relationship(back_populates="versions")
    uploader: Mapped[User] = relationship(lazy="joined")
    __table_args__ = (UniqueConstraint("document_id", "version_no", name="uq_version_no"),)


class Grant(Base):
    """One person, one document, one permission. Revoking = deleting the row."""
    __tablename__ = "grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    permission: Mapped[str] = mapped_column(String(8), nullable=False)
    granted_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    source: Mapped[str] = mapped_column(String(12), nullable=False, default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    user: Mapped[User] = relationship(foreign_keys=[user_id], lazy="joined")
    granter: Mapped[User] = relationship(foreign_keys=[granted_by], lazy="joined")
    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_grant_doc_user"),
        CheckConstraint("permission IN ('read','edit')", name="ck_grant_permission"),
        CheckConstraint("source IN ('manual','suggestion')", name="ck_grant_source"),
        Index("ix_grants_user_doc", "user_id", "document_id"),
    )


class AuditEvent(Base):
    """Append-only, hash-chained, HMAC-keyed evidence log.

    `seq` is assigned by the application under a lock (head + 1), not by a database
    sequence, so the chain is gap-free and any deleted row is detectable.
    Timestamps are stored as fixed-format strings so the hashed bytes can always be
    reproduced exactly, independent of database time-zone handling.
    """
    __tablename__ = "audit_events"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    occurred_at: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(36))
    actor_username: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_role: Mapped[str | None] = mapped_column(String(10))
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    outcome: Mapped[str] = mapped_column(String(8), nullable=False)
    document_id: Mapped[str | None] = mapped_column(String(64))
    target_user_id: Mapped[str | None] = mapped_column(String(36))
    ip: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(36))
    details: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    __table_args__ = (
        CheckConstraint("outcome IN ('success','denied','error')", name="ck_audit_outcome"),
        Index("ix_audit_time", "occurred_at"),
        Index("ix_audit_actor_time", "actor_id", "occurred_at"),
        Index("ix_audit_doc", "document_id"),
        Index("ix_audit_action_ip_time", "action", "ip", "occurred_at"),
    )


class AuditCheckpoint(Base):
    """Periodic copies of the chain head. Also written to the external anchor log."""
    __tablename__ = "audit_checkpoints"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(32), nullable=False)
