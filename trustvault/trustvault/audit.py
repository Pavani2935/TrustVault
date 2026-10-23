"""Tamper-evident audit ledger.

Layers of protection, from cheapest to strongest:

1. The application only ever INSERTs. Database triggers reject UPDATE, DELETE and
   TRUNCATE on the audit tables (see db.py).
2. Each event is chained to the previous one: entry_hash = HMAC-SHA256(audit_key,
   prev_hash | canonical_event). Editing, deleting or reordering any row breaks the
   chain from that point on.
3. The chain is keyed. The HMAC key lives in the environment, not in the database,
   so someone with write access to the database (but not the app's secrets) cannot
   recompute a valid chain after altering it. A plain SHA-256 chain would not stop them.
4. `seq` is assigned as head+1 under a lock inside the same transaction as the action
   it describes, so the sequence has no gaps; a missing number is a deleted event.
5. Every event and every checkpoint of the chain head is also written to the process
   log stream (and optionally an append-only anchor file). That copy lives outside the
   database, so even a full rewrite with the key, or truncation of the newest events,
   disagrees with what was shipped to the log system.

What it does not stop: someone holding BOTH database superuser rights and the
TV_AUDIT_KEY, who also controls the external log store. That is documented in THREATS.md.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import datetime, timezone

from flask import current_app, g, has_request_context, request
from sqlalchemy import event as sa_event
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .models import AuditCheckpoint, AuditEvent

log = logging.getLogger("trustvault.audit")
anchor_log = logging.getLogger("trustvault.audit.anchor")

GENESIS = "0" * 64
_PG_LOCK_KEY = 7262021  # arbitrary constant for pg_advisory_xact_lock


def timestamp(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(fields: dict) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hashed_fields(ev: AuditEvent) -> dict:
    return {
        "seq": ev.seq, "event_id": ev.event_id, "occurred_at": ev.occurred_at,
        "actor_id": ev.actor_id, "actor_username": ev.actor_username, "actor_role": ev.actor_role,
        "action": ev.action, "outcome": ev.outcome, "document_id": ev.document_id,
        "target_user_id": ev.target_user_id, "ip": ev.ip, "request_id": ev.request_id,
        "details": ev.details, "prev_hash": ev.prev_hash,
    }


def compute_hash(key: bytes, ev: AuditEvent) -> str:
    message = (ev.prev_hash + "|" + _canonical(_hashed_fields(ev))).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _clean(value, limit: int) -> str | None:
    if value is None:
        return None
    value = "".join(ch for ch in str(value) if ch.isprintable())
    return value[:limit]


def _lock_chain(db: Session) -> None:
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _PG_LOCK_KEY})
    # SQLite: every transaction already begins with BEGIN IMMEDIATE (db.py), which
    # holds the database write lock until commit, so the head cannot move under us.


def record(db: Session, *, action: str, outcome: str = "success", actor=None,
           actor_label: str | None = None, document_id: str | None = None,
           target_user_id: str | None = None, details: dict | None = None) -> AuditEvent:
    """Append one event inside the caller's transaction. The caller commits.

    Because the event is written in the same transaction as the change it describes,
    there can be no committed change without its audit record, and no audit record
    for a change that was rolled back.
    """
    if outcome not in ("success", "denied", "error"):
        raise ValueError("bad outcome")
    settings = current_app.config["TV_SETTINGS"]
    _lock_chain(db)
    head = db.execute(select(AuditEvent.seq, AuditEvent.entry_hash).order_by(AuditEvent.seq.desc()).limit(1)).first()
    seq, prev_hash = (head[0] + 1, head[1]) if head else (1, GENESIS)

    ip = request_id = None
    if has_request_context():
        ip = request.remote_addr
        request_id = getattr(g, "request_id", None)

    ev = AuditEvent(
        seq=seq,
        event_id=str(uuid.uuid4()),
        occurred_at=timestamp(),
        actor_id=getattr(actor, "id", None),
        actor_username=_clean(getattr(actor, "username", None) or actor_label or "anonymous", 64),
        actor_role=getattr(actor, "role", None),
        action=action,
        outcome=outcome,
        document_id=_clean(document_id, 64),
        target_user_id=target_user_id,
        ip=_clean(ip, 64),
        request_id=request_id,
        details=_canonical(details or {}),
        prev_hash=prev_hash,
    )
    ev.entry_hash = compute_hash(settings.audit_key, ev)
    db.add(ev)
    pending = db.info.setdefault("tv_audit_pending", [])
    pending.append(ev)
    if seq % settings.audit_checkpoint_every == 0:
        db.add(AuditCheckpoint(seq=seq, entry_hash=ev.entry_hash, created_at=ev.occurred_at))
        db.info.setdefault("tv_anchor_pending", []).append((seq, ev.entry_hash, ev.occurred_at))
    db.flush()
    return ev


def checkpoint_now(db: Session) -> dict | None:
    """Anchor the current head immediately (used by the admin verify action and the CLI)."""
    _lock_chain(db)
    head = db.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).scalar_one_or_none()
    if head is None:
        return None
    if db.get(AuditCheckpoint, head.seq) is None:
        db.add(AuditCheckpoint(seq=head.seq, entry_hash=head.entry_hash, created_at=timestamp()))
        db.info.setdefault("tv_anchor_pending", []).append((head.seq, head.entry_hash, timestamp()))
    return {"seq": head.seq, "entry_hash": head.entry_hash}


# --- external copies, emitted only after the transaction really committed -------------

def _emit_after_commit(session: Session) -> None:
    events = session.info.pop("tv_audit_pending", [])
    anchors = session.info.pop("tv_anchor_pending", [])
    for ev in events:
        log.info(json.dumps({"audit": _hashed_fields(ev) | {"entry_hash": ev.entry_hash}}, separators=(",", ":")))
    if anchors:
        anchor_file = None
        try:
            anchor_file = current_app.config["TV_SETTINGS"].audit_anchor_file
        except RuntimeError:
            pass
        for seq, entry_hash, at in anchors:
            line = json.dumps({"audit_anchor": {"seq": seq, "entry_hash": entry_hash, "at": at}})
            anchor_log.warning(line)
            if anchor_file:
                with open(anchor_file, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")


def _discard_after_rollback(session: Session) -> None:
    session.info.pop("tv_audit_pending", None)
    session.info.pop("tv_anchor_pending", None)


sa_event.listen(Session, "after_commit", _emit_after_commit)
sa_event.listen(Session, "after_rollback", _discard_after_rollback)


# --- verification ----------------------------------------------------------------------

def verify_chain(db: Session, key: bytes, external_anchors: list[dict] | None = None) -> dict:
    """Recompute the whole chain. Returns a report; never raises on tampering."""
    problems: list[str] = []
    expected_seq, expected_prev = 1, GENESIS
    hashes: dict[int, str] = {}
    count = 0
    stmt = select(AuditEvent).order_by(AuditEvent.seq).execution_options(yield_per=1000)
    for ev in db.execute(stmt).scalars():
        count += 1
        if ev.seq != expected_seq:
            problems.append(f"sequence gap: expected #{expected_seq}, found #{ev.seq} (events deleted?)")
            expected_seq = ev.seq
        if ev.prev_hash != expected_prev:
            problems.append(f"#{ev.seq}: prev_hash does not match the previous event (chain broken)")
        if not hmac.compare_digest(compute_hash(key, ev), ev.entry_hash):
            problems.append(f"#{ev.seq}: content does not match its HMAC (event altered)")
        hashes[ev.seq] = ev.entry_hash
        expected_prev = ev.entry_hash
        expected_seq += 1
        if len(problems) > 50:
            problems.append("too many problems; stopping")
            break

    head_seq = expected_seq - 1 if count else 0
    anchors = [{"seq": c.seq, "entry_hash": c.entry_hash} for c in db.execute(select(AuditCheckpoint)).scalars()]
    anchors += external_anchors or []
    for anchor in anchors:
        seq, h = int(anchor["seq"]), anchor["entry_hash"]
        if seq > head_seq:
            problems.append(f"checkpoint #{seq} is beyond the current head #{head_seq} (newest events truncated)")
        elif hashes.get(seq) != h:
            problems.append(f"checkpoint #{seq} does not match the stored event (history rewritten)")

    return {
        "valid": not problems,
        "events": count,
        "head_seq": head_seq,
        "head_hash": expected_prev if count else GENESIS,
        "checkpoints_checked": len(anchors),
        "problems": problems,
        "verified_at": timestamp(),
    }


def read_anchor_file(path: str) -> list[dict]:
    anchors = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    anchors.append(json.loads(line)["audit_anchor"])
    except FileNotFoundError:
        pass
    return anchors


def count_recent(db: Session, *, action: str, since: str, outcome: str | None = None,
                 ip: str | None = None, actor_username: str | None = None) -> int:
    stmt = select(func.count()).select_from(AuditEvent).where(AuditEvent.action == action, AuditEvent.occurred_at >= since)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if ip:
        stmt = stmt.where(AuditEvent.ip == ip)
    if actor_username:
        stmt = stmt.where(AuditEvent.actor_username == actor_username)
    return db.execute(stmt).scalar_one()
