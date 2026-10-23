"""T-20..T-29: taking access away works immediately, and whatever was issued stops working."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from conftest import Client


def test_revoked_grant_stops_working_on_the_next_request(ids, client_for):
    olivia, victor = client_for("olivia"), client_for("victor")
    doc = ids["docs"]["offer"]
    assert victor.get(f"/api/v1/documents/{doc}/download").status_code == 200
    assert olivia.delete(f"/api/v1/documents/{doc}/grants/{ids['users']['victor']}").status_code == 200
    # Same browser session, same URLs, no re-login: refused immediately.
    assert victor.get(f"/api/v1/documents/{doc}/download").status_code == 404
    assert victor.get(f"/api/v1/documents/{doc}/download?version=1").status_code == 404
    assert victor.get(f"/api/v1/documents/{doc}").status_code == 404
    assert victor.get("/api/v1/documents").get_json()["total"] == 0


def test_downgrading_edit_to_read_takes_effect_immediately(ids, client_for):
    olivia, vera = client_for("olivia"), client_for("vera")
    doc = ids["docs"]["drawing"]
    assert vera.patch(f"/api/v1/documents/{doc}", json={"title": "Layout rev 4"}).status_code == 200
    assert olivia.put(f"/api/v1/documents/{doc}/grants/{ids['users']['vera']}", json={"permission": "read"}).status_code == 200
    assert vera.patch(f"/api/v1/documents/{doc}", json={"title": "Layout rev 5"}).status_code == 403
    assert vera.get(f"/api/v1/documents/{doc}/download").status_code == 200


def test_deactivation_kills_existing_sessions_and_blocks_login(ids, client_for, app):
    victor = client_for("victor")
    doc = ids["docs"]["offer"]
    assert victor.get(f"/api/v1/documents/{doc}/download").status_code == 200
    res = client_for("admin").patch(f"/api/v1/admin/users/{ids['users']['victor']}", json={"is_active": False})
    assert res.status_code == 200 and res.get_json()["active_sessions"] == 0
    assert victor.get(f"/api/v1/documents/{doc}/download").status_code == 401
    assert victor.get("/api/v1/auth/me").status_code == 401
    assert Client(app).login("victor").status_code == 401


def test_deactivated_user_with_stolen_cookie_is_refused_even_if_session_row_survives(app, ids, client_for):
    """Defence in depth: even if a session row were left behind, an inactive account is refused."""
    from trustvault.db import get_db
    from trustvault.models import User
    victor = client_for("victor")
    with app.app_context():
        db = get_db()
        db.execute(update(User).where(User.username == "victor").values(is_active=False))
        db.commit()
    assert victor.get(f"/api/v1/documents/{ids['docs']['offer']}").status_code == 401


def test_role_change_ends_sessions(ids, client_for):
    oscar_doc = ids["docs"]["q2"]
    vera = client_for("vera")
    assert vera.get(f"/api/v1/documents/{oscar_doc}").status_code == 200
    assert client_for("admin").patch(f"/api/v1/admin/users/{ids['users']['vera']}", json={"role": "owner"}).status_code == 200
    assert vera.get(f"/api/v1/documents/{oscar_doc}").status_code == 401


def test_password_reset_ends_sessions(ids, client_for, app):
    victor = client_for("victor")
    res = client_for("admin").post(f"/api/v1/admin/users/{ids['users']['victor']}/reset-password",
                                   json={"password": "Temporary#Pass2026"})
    assert res.status_code == 200
    assert victor.get("/api/v1/documents").status_code == 401
    fresh = Client(app)
    assert fresh.login("victor", "Temporary#Pass2026").status_code == 200
    # A temporary password only lets you change it.
    assert fresh.get("/api/v1/documents").status_code == 403
    assert fresh.post("/api/v1/auth/change-password", json={
        "current_password": "Temporary#Pass2026", "new_password": "Own-Secret#Pass9"}).status_code == 200
    assert fresh.get("/api/v1/documents").status_code == 200


def test_changing_own_password_signs_out_other_sessions(app, client_for):
    laptop = client_for("victor")
    phone = Client(app)
    assert phone.login("victor").status_code == 200
    assert laptop.post("/api/v1/auth/change-password", json={
        "current_password": "Viewer#Vault2026", "new_password": "Brand-New#Pass42"}).status_code == 200
    assert laptop.get("/api/v1/auth/me").status_code == 200
    assert phone.get("/api/v1/auth/me").status_code == 401


def test_logout_invalidates_the_token_server_side(app, client_for):
    victor = client_for("victor")
    stolen = victor.session_cookie()
    assert victor.post("/api/v1/auth/logout").status_code == 200
    attacker = Client(app)
    attacker.http.set_cookie(app.config["TV_SETTINGS"].session_cookie_name, stolen)
    assert attacker.get("/api/v1/documents").status_code == 401


def test_admin_can_end_all_sessions(ids, client_for):
    victor = client_for("victor")
    assert client_for("admin").post(f"/api/v1/admin/users/{ids['users']['victor']}/revoke-sessions").get_json()["sessions_ended"] == 1
    assert victor.get("/api/v1/documents").status_code == 401


def test_idle_and_absolute_session_expiry(app, client_for):
    from trustvault.db import get_db
    from trustvault.models import Session
    victor = client_for("victor")
    with app.app_context():
        db = get_db()
        db.execute(update(Session).values(last_seen_at=datetime.now(timezone.utc) - timedelta(minutes=31)))
        db.commit()
    assert victor.get("/api/v1/documents").status_code == 401

    vera = client_for("vera")
    with app.app_context():
        db = get_db()
        db.execute(update(Session).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        db.commit()
    assert vera.get("/api/v1/documents").status_code == 401


def test_trash_removes_access_and_restore_brings_back_existing_grants(ids, client_for):
    olivia, victor = client_for("olivia"), client_for("victor")
    doc = ids["docs"]["offer"]
    olivia.delete(f"/api/v1/documents/{doc}")
    assert victor.get(f"/api/v1/documents/{doc}").status_code == 404
    assert olivia.post(f"/api/v1/documents/{doc}/restore").status_code == 200
    assert victor.get(f"/api/v1/documents/{doc}").status_code == 200


def test_purge_destroys_document_and_keys(app, ids, client_for):
    from sqlalchemy import func, select

    from trustvault.db import get_db
    from trustvault.models import Blob, DocumentVersion, Grant
    olivia = client_for("olivia")
    doc = ids["docs"]["offer"]
    assert olivia.delete(f"/api/v1/documents/{doc}/purge", json={"confirm": "PURGE"}).status_code == 403  # not in trash yet
    olivia.delete(f"/api/v1/documents/{doc}")
    assert olivia.delete(f"/api/v1/documents/{doc}/purge").status_code == 400  # needs explicit confirmation
    assert olivia.delete(f"/api/v1/documents/{doc}/purge", json={"confirm": "PURGE"}).status_code == 200
    assert olivia.get(f"/api/v1/documents/{doc}").status_code == 404
    with app.app_context():
        db = get_db()
        assert db.execute(select(func.count()).select_from(DocumentVersion).where(DocumentVersion.document_id == doc)).scalar_one() == 0
        assert db.execute(select(func.count()).select_from(Grant).where(Grant.document_id == doc)).scalar_one() == 0
        assert db.execute(select(func.count()).select_from(Blob)).scalar_one() == 6  # 7 seeded, 1 purged


def test_ownership_transfer_removes_previous_owner(ids, client_for):
    admin, olivia, oscar = client_for("admin"), client_for("olivia"), client_for("oscar")
    doc = ids["docs"]["salary"]
    res = admin.post(f"/api/v1/admin/documents/{doc}/transfer",
                     json={"new_owner_id": ids["users"]["oscar"], "reason": "Olivia moved to another team"})
    assert res.status_code == 200
    assert olivia.get(f"/api/v1/documents/{doc}").status_code == 404
    assert oscar.get(f"/api/v1/documents/{doc}").get_json()["my_permission"] == "owner"


def test_downloads_are_never_cacheable(ids, client_for):
    res = client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    assert res.status_code == 200
    assert res.headers["Cache-Control"] == "no-store"
    assert res.headers["Content-Disposition"].startswith("attachment;")
    assert res.headers["Content-Type"] == "application/octet-stream"
