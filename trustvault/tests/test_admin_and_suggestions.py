"""T-90..T-99: administration rules, alerts, and the access-suggestion feature."""
from __future__ import annotations

import json

from conftest import Client, audit_rows


def test_admin_creates_user_who_must_change_password(app, client_for):
    res = client_for("admin").post("/api/v1/admin/users", json={
        "username": "priya.n", "display_name": "Priya N", "role": "viewer", "password": "Welcome#2026abc"})
    assert res.status_code == 201
    c = Client(app)
    assert c.login("priya.n", "Welcome#2026abc").status_code == 200
    assert c.get("/api/v1/documents").get_json()["error"]["code"] == "password_change_required"


def test_duplicate_usernames_are_rejected_case_insensitively(client_for):
    res = client_for("admin").post("/api/v1/admin/users", json={"username": "Olivia", "role": "viewer", "password": "Welcome#2026abc"})
    assert res.status_code == 409


def test_admin_cannot_lock_themselves_out(ids, client_for):
    admin = client_for("admin")
    assert admin.patch(f"/api/v1/admin/users/{ids['users']['admin']}", json={"role": "viewer"}).status_code == 409
    assert admin.patch(f"/api/v1/admin/users/{ids['users']['admin']}", json={"is_active": False}).status_code == 409


def test_owner_with_documents_cannot_be_demoted_until_transfer(ids, client_for):
    admin = client_for("admin")
    res = admin.patch(f"/api/v1/admin/users/{ids['users']['oscar']}", json={"role": "viewer"})
    assert res.status_code == 409 and res.get_json()["error"]["code"] == "owns_documents"


def test_transfer_only_to_active_owners_and_requires_reason(ids, client_for):
    admin = client_for("admin")
    doc = ids["docs"]["board"]
    assert admin.post(f"/api/v1/admin/documents/{doc}/transfer", json={"new_owner_id": ids["users"]["victor"], "reason": "x"}).status_code == 400
    assert admin.post(f"/api/v1/admin/documents/{doc}/transfer", json={"new_owner_id": ids["users"]["admin"], "reason": "x"}).status_code == 400
    assert admin.post(f"/api/v1/admin/documents/{doc}/transfer", json={"new_owner_id": ids["users"]["olivia"], "reason": ""}).status_code == 400
    assert client_for("oscar").post(f"/api/v1/admin/documents/{doc}/transfer", json={"new_owner_id": ids["users"]["olivia"], "reason": "x"}).status_code == 403


def test_demo_mode_protects_shared_demo_accounts_and_seed_documents(make):
    app = make(demo_mode=True)
    admin = Client(app)
    admin.login("admin")
    users = {u["username"]: u["id"] for u in admin.get("/api/v1/admin/users").get_json()["items"]}
    assert admin.patch(f"/api/v1/admin/users/{users['olivia']}", json={"is_active": False}).status_code == 403
    assert admin.post(f"/api/v1/admin/users/{users['olivia']}/reset-password", json={"password": "Another#Pass2026"}).status_code == 403
    victor = Client(app)
    victor.login("victor")
    assert victor.post("/api/v1/auth/change-password", json={"current_password": "Viewer#Vault2026", "new_password": "Another#Pass2026"}).status_code == 403
    olivia = Client(app)
    olivia.login("olivia")
    doc = olivia.get("/api/v1/documents?q=salary").get_json()["items"][0]["id"]
    olivia.delete(f"/api/v1/documents/{doc}")
    assert olivia.delete(f"/api/v1/documents/{doc}/purge", json={"confirm": "PURGE"}).status_code == 403
    assert olivia.post(f"/api/v1/documents/{doc}/restore").status_code == 200
    oscar_id = users["oscar"]
    assert admin.post(f"/api/v1/admin/documents/{doc}/transfer", json={"new_owner_id": oscar_id, "reason": "x"}).status_code == 403


def test_probing_raises_an_alert(ids, client_for):
    victor = client_for("victor")
    for key in ("salary", "msa", "drawing", "q2", "board", "q3"):
        victor.get(f"/api/v1/documents/{ids['docs'][key]}/download")
    alerts = client_for("admin").get("/api/v1/admin/overview").get_json()["alerts"]
    probing = [a for a in alerts if a["kind"] == "access_probing"]
    assert probing and "victor" in probing[0]["message"] and probing[0]["severity"] == "high"


def test_leaver_download_pattern_raises_an_alert(ids, client_for):
    client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    admin = client_for("admin")
    admin.patch(f"/api/v1/admin/users/{ids['users']['victor']}", json={"is_active": False})
    kinds = {a["kind"] for a in admin.get("/api/v1/admin/overview").get_json()["alerts"]}
    assert "leaver_downloads" in kinds


def test_new_admin_raises_an_alert(client_for):
    admin = client_for("admin")
    admin.post("/api/v1/admin/users", json={"username": "second.admin", "role": "admin", "password": "Welcome#2026abc"})
    assert any(a["kind"] == "new_admin" for a in admin.get("/api/v1/admin/overview").get_json()["alerts"])


# --- suggestions --------------------------------------------------------------------------

def test_suggestions_are_explainable_and_never_grant_by_themselves(app, ids, client_for):
    oscar = client_for("oscar")
    doc = ids["docs"]["q3"]  # Audit category; Vera already holds Oscar's other Audit document
    res = oscar.get(f"/api/v1/documents/{doc}/suggestions").get_json()["items"]
    by_name = {s["user"]["username"]: s for s in res}
    assert set(by_name) == {"vera", "olivia"}  # both already hold Oscar's other Audit document
    assert "'Audit'" in by_name["vera"]["reasons"][0]
    assert client_for("vera").get(f"/api/v1/documents/{doc}").status_code == 404  # still no access
    shown = audit_rows(app, action="suggestion.shown")[-1]
    assert {s["username"] for s in json.loads(shown.details)["suggested"]} == {"vera", "olivia"}


def test_accepting_a_suggestion_is_a_recorded_human_decision(app, ids, client_for):
    oscar = client_for("oscar")
    doc = ids["docs"]["q3"]
    oscar.get(f"/api/v1/documents/{doc}/suggestions")
    res = oscar.put(f"/api/v1/documents/{doc}/grants/{ids['users']['vera']}", json={"permission": "read", "source": "suggestion"})
    assert res.status_code == 200 and res.get_json()["source"] == "suggestion"
    ev = audit_rows(app, action="grant.set")[-1]
    details = json.loads(ev.details)
    assert ev.actor_username == "oscar" and details["source"] == "suggestion" and details["suggestion"]["reasons"]


def test_grant_cannot_be_falsely_labelled_as_suggested(ids, client_for):
    res = client_for("oscar").put(f"/api/v1/documents/{ids['docs']['q3']}/grants/{ids['users']['victor']}",
                                  json={"permission": "read", "source": "suggestion"})
    assert res.status_code == 400


def test_dismissal_is_recorded(app, ids, client_for):
    oscar = client_for("oscar")
    doc = ids["docs"]["q3"]
    assert oscar.post(f"/api/v1/documents/{doc}/suggestions/{ids['users']['vera']}/dismiss").status_code == 200
    assert audit_rows(app, action="suggestion.dismissed")


def test_suggestions_never_include_admins_or_inactive_people(ids, client_for):
    admin = client_for("admin")
    oscar = client_for("oscar")
    admin.patch(f"/api/v1/admin/users/{ids['users']['vera']}", json={"is_active": False})
    names = [s["user"]["username"] for s in oscar.get(f"/api/v1/documents/{ids['docs']['q3']}/suggestions").get_json()["items"]]
    assert "vera" not in names and "admin" not in names
