"""T-02: the policy function itself, checked exhaustively against an independent statement of the rules."""
from __future__ import annotations

import itertools
from datetime import datetime, timezone
from types import SimpleNamespace as NS

import pytest

from trustvault.security.policy import Action, decide

READ = {Action.VIEW, Action.DOWNLOAD}
EDIT = READ | {Action.EDIT_METADATA, Action.UPLOAD_VERSION}


def reference(role_is_owner, grant, active, deleted, action):
    """The rules written out independently of the implementation."""
    if not active:
        return False
    if role_is_owner:
        if deleted:
            return action in {Action.VIEW, Action.RESTORE, Action.PURGE, Action.VIEW_ACTIVITY}
        return action not in {Action.RESTORE, Action.PURGE}
    if deleted or grant is None:
        return False
    return action in (EDIT if grant == "edit" else READ)


CASES = list(itertools.product(
    [True, False],                 # actor is the document owner
    [None, "read", "edit"],        # grant held by actor
    [True, False],                 # actor active
    [True, False],                 # document deleted
    ["admin", "owner", "viewer"],  # actor role: must make NO difference
    list(Action),
))


@pytest.mark.parametrize("is_owner,grant,active,deleted,role,action", CASES)
def test_decide_matches_reference(is_owner, grant, active, deleted, role, action):
    actor = NS(id="u1", is_active=active, role=role)
    doc = NS(id="d1", owner_id="u1" if is_owner else "u2",
             deleted_at=datetime.now(timezone.utc) if deleted else None)
    g = NS(user_id="u1", document_id="d1", permission=grant) if grant else None
    assert decide(actor, doc, action, g).allowed == reference(is_owner, grant, active, deleted, action)


def test_grant_for_another_user_or_document_is_ignored():
    actor = NS(id="u1", is_active=True, role="viewer")
    doc = NS(id="d1", owner_id="u2", deleted_at=None)
    assert not decide(actor, doc, Action.VIEW, NS(user_id="u3", document_id="d1", permission="edit")).allowed
    assert not decide(actor, doc, Action.VIEW, NS(user_id="u1", document_id="d9", permission="edit")).allowed
    assert not decide(actor, doc, Action.VIEW, NS(user_id="u1", document_id="d1", permission="owner")).allowed


def test_missing_document_or_actor_is_denied_as_not_found():
    actor = NS(id="u1", is_active=True, role="admin")
    assert decide(actor, None, Action.VIEW).http_status == 404
    assert decide(None, NS(id="d1", owner_id="u1", deleted_at=None), Action.VIEW).http_status == 404
