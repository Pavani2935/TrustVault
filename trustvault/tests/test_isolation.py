"""T-01..T-12: one user cannot reach another user's documents, through any route.

The core test is a full matrix: every seeded document x every person x every
document endpoint, compared against the ground truth in conftest.TRUTH.
"""
from __future__ import annotations

import io
import itertools
import uuid

import pytest

from conftest import TITLES, TRUTH, USERS, Client, audit_rows

LEVEL = {None: 0, "read": 1, "edit": 2, "owner": 3}


def expected(perm, needed):
    """Status the API must return for a caller with `perm` attempting an action needing `needed`."""
    if LEVEL[perm] >= LEVEL[needed]:
        return "ok"
    return 404 if perm is None else 403


def _txt(content=b"new version\n", name="v.txt"):
    return {"file": (io.BytesIO(content), name)}


@pytest.mark.parametrize("doc_key,username", list(itertools.product(TRUTH, USERS)))
def test_access_matrix(app, ids, client_for, doc_key, username):
    c = client_for(username)
    doc_id = ids["docs"][doc_key]
    owner = next(u for u, p in TRUTH[doc_key].items() if p == "owner")
    perm = TRUTH[doc_key].get(username)
    target = next(u for u in ("victor", "vera", "admin") if u not in (username, owner))
    target_id = ids["users"][target]
    base = f"/api/v1/documents/{doc_id}"

    checks = [
        ("view", lambda: c.get(base), "read"),
        ("download", lambda: c.get(f"{base}/download"), "read"),
        ("download v1", lambda: c.get(f"{base}/download?version=1"), "read"),
        ("download HEAD", lambda: c.head(f"{base}/download"), "read"),
        ("activity", lambda: c.get(f"{base}/activity"), "owner"),
        ("list grants", lambda: c.get(f"{base}/grants"), "owner"),
        ("suggestions", lambda: c.get(f"{base}/suggestions"), "owner"),
        ("edit metadata", lambda: c.patch(base, json={"title": "Renamed by test"}), "edit"),
        ("upload version", lambda: c.post(f"{base}/versions", data=_txt(), content_type="multipart/form-data"), "edit"),
        ("grant", lambda: c.put(f"{base}/grants/{target_id}", json={"permission": "read"}), "owner"),
        ("revoke", lambda: c.delete(f"{base}/grants/{target_id}"), "owner"),
    ]
    denied = 0
    for name, call, needed in checks:
        res = call()
        want = expected(perm, needed)
        if want == "ok":
            assert res.status_code in (200, 201), f"{username} {name} on {doc_key}: {res.status_code} {res.get_data(as_text=True)[:200]}"
        else:
            denied += 1
            assert res.status_code == want, f"{username} {name} on {doc_key}: expected {want}, got {res.status_code}"
            body = res.get_data(as_text=True)
            assert TITLES[doc_key] not in body, "a refusal must not leak the document title"
            if name.startswith("download"):
                assert b"sample" not in res.data.lower()

    # Restore / purge only apply to documents in the trash: refused for everyone here.
    assert c.post(f"{base}/restore").status_code == (404 if perm is None else 403)
    assert c.delete(f"{base}/purge", json={"confirm": "PURGE"}).status_code == (404 if perm is None else 403)
    denied += 2

    res = c.delete(base)
    if perm == "owner":
        assert res.status_code == 200
    else:
        assert res.status_code == (404 if perm is None else 403)
        denied += 1
        # ...and the document is still there for its owner.
        assert client_for(owner).get(base).status_code == 200

    refused = [e for e in audit_rows(app, actor_username=username, outcome="denied") if e.document_id == doc_id]
    assert len(refused) == denied, "every refused attempt must be in the audit trail"


def test_search_never_returns_documents_you_cannot_open(app, ids, client_for):
    for username in USERS:
        c = client_for(username)
        allowed = {ids["docs"][k] for k, perms in TRUTH.items() if username in perms}
        seen = set()
        for params in ("", "?q=a", "?q=%25", "?q=_", "?owner=o", "?category=Board", "?category=HR",
                       "?from=2000-01-01&to=2100-01-01", "?limit=100", "?sort=title", "?q=board"):
            res = c.get(f"/api/v1/documents{params}")
            assert res.status_code == 200
            seen |= {d["id"] for d in res.get_json()["items"]}
        assert seen <= allowed, f"{username} saw documents outside their grants"
        if username != "admin":
            assert seen == allowed


def test_search_like_wildcards_are_literal(client_for):
    c = client_for("victor")
    assert c.get("/api/v1/documents?q=%25").get_json()["total"] == 0
    assert c.get("/api/v1/documents?q=_").get_json()["total"] == 0


def test_categories_only_show_accessible_documents(client_for):
    assert client_for("victor").get("/api/v1/categories").get_json()["items"] == ["HR"]
    assert client_for("admin").get("/api/v1/categories").get_json()["items"] == []
    assert "Board" not in client_for("olivia").get("/api/v1/categories").get_json()["items"]


def test_administrator_cannot_read_any_document_content(ids, client_for):
    admin = client_for("admin")
    for doc_id in ids["docs"].values():
        assert admin.get(f"/api/v1/documents/{doc_id}").status_code == 404
        assert admin.get(f"/api/v1/documents/{doc_id}/download").status_code == 404
    listing = admin.get("/api/v1/admin/documents").get_json()["items"]
    assert len(listing) == 7
    assert all("versions" not in d and "latest_version" not in d for d in listing)


def test_nonexistent_and_forbidden_look_identical(ids, client_for):
    c = client_for("victor")
    real = c.get(f"/api/v1/documents/{ids['docs']['board']}")
    fake = c.get(f"/api/v1/documents/{uuid.uuid4()}")
    assert real.status_code == fake.status_code == 404
    strip = lambda r: {k: v for k, v in r.get_json()["error"].items() if k != "request_id"}  # noqa: E731
    assert strip(real) == strip(fake)


@pytest.mark.parametrize("bad_id", [
    "..%2F..%2Fetc%2Fpasswd", "1", "' OR '1'='1", "%00", "x" * 300,
    "00000000-0000-0000-0000-000000000000",
])
def test_malformed_document_ids_are_refused_and_logged(app, client_for, bad_id):
    c = client_for("victor")
    for path in (f"/api/v1/documents/{bad_id}", f"/api/v1/documents/{bad_id}/download"):
        assert c.get(path).status_code == 404
    if "%2F" not in bad_id:  # an encoded slash never even matches a document route
        assert audit_rows(app, actor_username="victor", outcome="denied")


def test_uppercase_uuid_is_authorised_the_same_way(ids, client_for):
    upper = ids["docs"]["offer"].upper()
    assert client_for("victor").get(f"/api/v1/documents/{upper}").status_code == 200
    assert client_for("vera").get(f"/api/v1/documents/{upper}").status_code == 404


@pytest.mark.parametrize("version", ["0", "-1", "99", "1 OR 1=1", "../1", "1.0", "abc"])
def test_version_parameter_cannot_escape_the_document(ids, client_for, version):
    res = client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download?version={version}")
    assert res.status_code in (400, 404)


def test_edit_grantee_cannot_reshare_delete_or_see_grants(ids, client_for):
    vera = client_for("vera")
    doc = ids["docs"]["drawing"]
    assert vera.put(f"/api/v1/documents/{doc}/grants/{ids['users']['victor']}", json={"permission": "read"}).status_code == 403
    assert vera.put(f"/api/v1/documents/{doc}/grants/{ids['users']['vera']}", json={"permission": "edit"}).status_code == 403
    assert vera.get(f"/api/v1/documents/{doc}/grants").status_code == 403
    assert vera.delete(f"/api/v1/documents/{doc}").status_code == 403
    assert client_for("victor").get(f"/api/v1/documents/{doc}").status_code == 404


def test_mass_assignment_of_owner_is_rejected(ids, client_for):
    vera = client_for("vera")
    doc = ids["docs"]["drawing"]
    res = vera.patch(f"/api/v1/documents/{doc}", json={"title": "x", "owner_id": ids["users"]["vera"]})
    assert res.status_code == 400
    assert client_for("olivia").get(f"/api/v1/documents/{doc}").get_json()["owner"]["username"] == "olivia"


def test_owner_cannot_grant_to_themselves_or_unknown_or_inactive(app, ids, client_for):
    olivia = client_for("olivia")
    doc = ids["docs"]["salary"]
    assert olivia.put(f"/api/v1/documents/{doc}/grants/{ids['users']['olivia']}", json={"permission": "edit"}).status_code == 400
    assert olivia.put(f"/api/v1/documents/{doc}/grants/{uuid.uuid4()}", json={"permission": "read"}).status_code == 404
    assert olivia.put(f"/api/v1/documents/{doc}/grants/{ids['users']['victor']}", json={"permission": "owner"}).status_code == 400
    admin = client_for("admin")
    admin.patch(f"/api/v1/admin/users/{ids['users']['victor']}", json={"is_active": False})
    assert olivia.put(f"/api/v1/documents/{doc}/grants/{ids['users']['victor']}", json={"permission": "read"}).status_code == 404


def test_only_owners_upload_new_documents(app, client_for):
    for username in ("victor", "admin"):
        res = client_for(username).post("/api/v1/documents", data={"title": "t", "category": "HR", **_txt()},
                                        content_type="multipart/form-data")
        assert res.status_code == 403
    assert audit_rows(app, action="document.create", outcome="denied")


def test_role_gated_endpoints(client_for):
    for username in ("olivia", "victor"):
        c = client_for(username)
        for path in ("/api/v1/admin/overview", "/api/v1/admin/users", "/api/v1/admin/audit", "/api/v1/admin/documents"):
            assert c.get(path).status_code == 403
        assert c.post("/api/v1/admin/audit/verify").status_code == 403
    assert client_for("victor").get("/api/v1/users/directory").status_code == 403
    assert client_for("victor").get("/api/v1/documents/trash").status_code == 403


def test_unauthenticated_requests_get_nothing(app, ids):
    anon = Client(app)
    doc = ids["docs"]["offer"]
    for path in ("/api/v1/documents", f"/api/v1/documents/{doc}", f"/api/v1/documents/{doc}/download",
                 "/api/v1/categories", "/api/v1/admin/audit", "/api/v1/auth/me", "/api/v1/users/directory"):
        assert anon.get(path).status_code == 401
    assert anon.delete(f"/api/v1/documents/{doc}").status_code == 401


def test_trashed_document_is_invisible_to_grantees(ids, client_for):
    olivia, victor = client_for("olivia"), client_for("victor")
    doc = ids["docs"]["offer"]
    assert olivia.delete(f"/api/v1/documents/{doc}").status_code == 200
    assert victor.get(f"/api/v1/documents/{doc}").status_code == 404
    assert victor.get(f"/api/v1/documents/{doc}/download").status_code == 404
    assert victor.get("/api/v1/documents").get_json()["total"] == 0
    # The owner can see it in the trash but cannot modify or re-share it there.
    assert olivia.get(f"/api/v1/documents/{doc}").status_code == 200
    assert olivia.patch(f"/api/v1/documents/{doc}", json={"title": "x"}).status_code == 403
    assert olivia.put(f"/api/v1/documents/{doc}/grants/{ids['users']['vera']}", json={"permission": "read"}).status_code == 403
    assert olivia.get(f"/api/v1/documents/{doc}/download").status_code == 403
