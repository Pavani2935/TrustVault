"""THE authorisation decision for documents.

Every document operation, from every route, goes through `decide()`. There is no
other code path that grants access to a document, its versions, its bytes, its
grants or its activity. If you are looking for "where is the authorisation decision
made when someone downloads a file", it is here, called from
`services.documents.load_document()`.

Rules (deny by default):
- An inactive account can do nothing.
- The document owner can do everything to their own document.
- A document in the trash is invisible to everyone except its owner, who can
  view, restore, purge or inspect its activity, and nothing else.
- A `read` grant allows VIEW and DOWNLOAD.
- An `edit` grant additionally allows EDIT_METADATA and UPLOAD_VERSION.
- Nobody but the owner can delete, restore, purge, manage grants, see the
  document's activity log or ask for access suggestions. In particular an
  `edit` grantee cannot re-share, so access can never widen without the owner.
- The administrator role grants NOTHING here. Administrators manage identities and
  read the audit trail; they do not read documents unless an owner granted them.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Action(str, Enum):
    VIEW = "view"
    DOWNLOAD = "download"
    EDIT_METADATA = "edit_metadata"
    UPLOAD_VERSION = "upload_version"
    DELETE = "delete"
    RESTORE = "restore"
    PURGE = "purge"
    MANAGE_GRANTS = "manage_grants"
    VIEW_ACTIVITY = "view_activity"
    SUGGEST_ACCESS = "suggest_access"


READ_ACTIONS = frozenset({Action.VIEW, Action.DOWNLOAD})
EDIT_ACTIONS = READ_ACTIONS | {Action.EDIT_METADATA, Action.UPLOAD_VERSION}
OWNER_ACTIONS = frozenset(Action)
TRASH_OWNER_ACTIONS = frozenset({Action.VIEW, Action.RESTORE, Action.PURGE, Action.VIEW_ACTIVITY})

ALLOWED_BY_PERMISSION = {
    "owner": OWNER_ACTIONS,
    "edit": EDIT_ACTIONS,
    "read": READ_ACTIONS,
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    permission: str | None   # the caller's effective permission, if any
    reason: str

    @property
    def http_status(self) -> int:
        # No relationship with the document at all -> 404, indistinguishable from
        # "does not exist". Some relationship but not enough -> 403.
        return 200 if self.allowed else (404 if self.permission is None else 403)


def effective_permission(actor, document, grant) -> str | None:
    if actor is None or not actor.is_active or document is None:
        return None
    if document.owner_id == actor.id:
        return "owner"
    if document.deleted_at is not None:
        return None
    if grant is not None and grant.user_id == actor.id and grant.document_id == document.id:
        return grant.permission if grant.permission in ("read", "edit") else None
    return None


def decide(actor, document, action: Action, grant=None) -> Decision:
    if document is None:
        return Decision(False, None, "document not found")
    permission = effective_permission(actor, document, grant)
    if permission is None:
        return Decision(False, None, "no grant for this document")
    allowed_actions = ALLOWED_BY_PERMISSION[permission]
    if document.deleted_at is not None:
        allowed_actions = allowed_actions & TRASH_OWNER_ACTIONS
    elif action in (Action.RESTORE, Action.PURGE):
        # Restore/purge only make sense for a document that is already in the trash.
        return Decision(False, permission, "document is not in the trash")
    if action not in allowed_actions:
        return Decision(False, permission, f"'{permission}' does not allow {action.value}")
    return Decision(True, permission, "allowed")
