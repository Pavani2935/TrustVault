"""T-30..T-45: you can prove who reached a document, including refused attempts,
and the record cannot be quietly altered."""
from __future__ import annotations

import hashlib
import json
import threading

import pytest
from sqlalchemy.exc import DBAPIError

from conftest import Client, audit_rows, is_postgres, raw_sql


def _verify(app):
    from trustvault import audit
    from trustvault.db import get_db
    with app.app_context():
        return audit.verify_chain(get_db(), app.config["TV_SETTINGS"].audit_key)


def _drop_protection(app):
    """Simulate a database superuser who disables the append-only triggers."""
    if is_postgres(app):
        raw_sql(app, "ALTER TABLE audit_events DISABLE TRIGGER USER")
    else:
        raw_sql(app, "DROP TRIGGER audit_events_no_update")
        raw_sql(app, "DROP TRIGGER audit_events_no_delete")


def test_download_is_recorded_with_who_what_when(app, ids, client_for):
    doc = ids["docs"]["offer"]
    client_for("victor").get(f"/api/v1/documents/{doc}/download")
    ev = audit_rows(app, action="document.download", outcome="success")[-1]
    assert ev.actor_username == "victor" and ev.actor_id == ids["users"]["victor"]
    assert ev.document_id == doc and ev.ip == "127.0.0.1" and ev.request_id
    details = json.loads(ev.details)
    assert details["version"] == 1 and len(details["sha256"]) == 64


def test_every_refusal_is_recorded_with_a_reason(app, ids, client_for):
    vera = client_for("vera")
    vera.get(f"/api/v1/documents/{ids['docs']['board']}/download")
    vera.patch(f"/api/v1/documents/{ids['docs']['msa']}", json={"title": "x"})
    rows = audit_rows(app, actor_username="vera", outcome="denied")
    assert [(r.action, json.loads(r.details)["reason"]) for r in rows] == [
        ("document.download", "no grant for this document"),
        ("document.edit_metadata", "'read' does not allow edit_metadata"),
    ]


def test_role_denials_and_failed_logins_are_recorded(app, client_for):
    client_for("victor").get("/api/v1/admin/audit")
    assert audit_rows(app, action="authz.role_denied", actor_username="victor")
    Client(app).login("olivia", "wrong-password")
    Client(app).login("nobody-at-all", "whatever")
    failed = audit_rows(app, action="auth.login", outcome="denied")
    assert [(f.actor_username, json.loads(f.details)["reason"]) for f in failed] == [
        ("olivia", "wrong password"), ("nobody-at-all", "unknown user")]


def test_uploads_edits_grants_deletions_are_all_recorded(app, ids, client_for):
    import io
    olivia = client_for("olivia")
    doc = ids["docs"]["salary"]
    olivia.patch(f"/api/v1/documents/{doc}", json={"category": "Payroll"})
    olivia.post(f"/api/v1/documents/{doc}/versions", data={"file": (io.BytesIO(b"a,b\n1,2\n"), "s.csv")},
                content_type="multipart/form-data")
    olivia.put(f"/api/v1/documents/{doc}/grants/{ids['users']['victor']}", json={"permission": "read"})
    olivia.delete(f"/api/v1/documents/{doc}/grants/{ids['users']['victor']}")
    olivia.delete(f"/api/v1/documents/{doc}")
    olivia.post(f"/api/v1/documents/{doc}/restore")
    actions = [e.action for e in audit_rows(app, document_id=doc, outcome="success")]
    for expected in ("document.create", "document.edit_metadata", "document.upload_version", "grant.set",
                     "grant.revoke", "document.delete", "document.restore"):
        assert expected in actions


def test_owner_sees_document_activity_but_grantee_does_not(ids, client_for):
    doc = ids["docs"]["offer"]
    client_for("victor").get(f"/api/v1/documents/{doc}/download")
    items = client_for("olivia").get(f"/api/v1/documents/{doc}/activity").get_json()["items"]
    assert any(e["action"] == "document.download" and e["actor"]["username"] == "victor" for e in items)
    assert client_for("victor").get(f"/api/v1/documents/{doc}/activity").status_code == 403


def test_chain_verifies_after_normal_use(app, ids, client_for):
    client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    client_for("vera").get(f"/api/v1/documents/{ids['docs']['board']}")
    report = client_for("admin").post("/api/v1/admin/audit/verify").get_json()
    assert report["valid"] and report["events"] >= 15 and not report["problems"]


@pytest.mark.parametrize("sql", ["UPDATE audit_events SET outcome='denied' WHERE seq = 1",
                                 "DELETE FROM audit_events WHERE seq = 1"])
def test_database_refuses_to_alter_audit_rows(app, sql):
    with pytest.raises(DBAPIError):
        raw_sql(app, sql)
    assert _verify(app)["valid"]


def test_database_refuses_truncate_on_postgres(app):
    if not is_postgres(app):
        pytest.skip("TRUNCATE exists only on PostgreSQL")
    with pytest.raises(DBAPIError):
        raw_sql(app, "TRUNCATE audit_events")


def test_edited_event_is_detected(app, ids, client_for):
    client_for("vera").get(f"/api/v1/documents/{ids['docs']['board']}/download")
    _drop_protection(app)
    raw_sql(app, "UPDATE audit_events SET outcome='success', details='{}' WHERE outcome='denied'")
    report = _verify(app)
    assert not report["valid"]
    assert any("altered" in p for p in report["problems"])


def test_deleted_event_is_detected(app):
    _drop_protection(app)
    raw_sql(app, "DELETE FROM audit_events WHERE seq = 5")
    report = _verify(app)
    assert not report["valid"]
    # An investigator needs to know WHICH event is missing, not only that the chain broke after it.
    assert any("sequence gap: expected #5, found #6" in p for p in report["problems"])


def test_rewriting_the_chain_without_the_secret_key_is_detected(app, ids, client_for):
    """An attacker with database write access edits a row and recomputes every hash
    after it. Without TV_AUDIT_KEY they cannot produce valid HMACs."""
    from trustvault import audit as audit_mod
    client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    _drop_protection(app)
    rows = audit_rows(app)
    target = next(r for r in rows if r.action == "document.download")
    target.actor_username = "olivia"
    prev = target.prev_hash
    forged = {}
    for r in rows[rows.index(target):]:
        r.prev_hash = prev
        guessed_key = hashlib.sha256(b"").digest()  # attacker does not know the real key
        r.entry_hash = audit_mod.compute_hash(guessed_key, r)
        forged[r.seq] = (r.prev_hash, r.entry_hash)
        prev = r.entry_hash
    raw_sql(app, "UPDATE audit_events SET actor_username='olivia' WHERE seq=:s", s=target.seq)
    for seq, (p, e) in forged.items():
        raw_sql(app, "UPDATE audit_events SET prev_hash=:p, entry_hash=:e WHERE seq=:s", p=p, e=e, s=seq)
    report = _verify(app)
    assert not report["valid"]


def test_truncating_the_newest_events_is_detected_by_checkpoints(make):
    app = make(audit_checkpoint_every=5)
    head = _verify(app)["head_seq"]
    assert head >= 10
    if is_postgres(app):
        raw_sql(app, "ALTER TABLE audit_events DISABLE TRIGGER USER")
    else:
        raw_sql(app, "DROP TRIGGER audit_events_no_delete")
    raw_sql(app, "DELETE FROM audit_events WHERE seq > 7")  # chain 1..7 is still internally consistent
    report = _verify(app)
    assert not report["valid"]
    assert any("truncated" in p for p in report["problems"])


def test_external_anchor_file_catches_truncation_after_the_last_db_checkpoint(make, tmp_path):
    from trustvault import audit as audit_mod
    from trustvault.db import get_db
    anchors = tmp_path / "anchors.jsonl"
    app = make(audit_checkpoint_every=1000, audit_anchor_file=str(anchors))
    with app.app_context():
        db = get_db()
        audit_mod.checkpoint_now(db)
        db.commit()
    assert anchors.read_text().strip()
    if is_postgres(app):
        raw_sql(app, "ALTER TABLE audit_events DISABLE TRIGGER USER")
        raw_sql(app, "ALTER TABLE audit_checkpoints DISABLE TRIGGER USER")
    else:
        for t in ("audit_events_no_delete", "audit_checkpoints_no_delete"):
            raw_sql(app, f"DROP TRIGGER {t}")
    raw_sql(app, "DELETE FROM audit_checkpoints")
    raw_sql(app, "DELETE FROM audit_events WHERE seq > 3")
    with app.app_context():
        report = audit_mod.verify_chain(get_db(), app.config["TV_SETTINGS"].audit_key,
                                        audit_mod.read_anchor_file(str(anchors)))
    assert not report["valid"]


def test_concurrent_requests_keep_the_chain_gap_free(app, ids):
    clients = []
    for name in ("victor", "vera", "olivia", "oscar"):
        c = Client(app)
        c.login(name)
        clients.append(c)
    doc = ids["docs"]["q2"]
    errors = []

    def worker(c):
        try:
            for _ in range(5):
                r = c.get(f"/api/v1/documents/{doc}/download")
                assert r.status_code in (200, 404)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    threads = [threading.Thread(target=worker, args=(c,)) for c in clients]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    report = _verify(app)
    assert report["valid"], report["problems"]
    seqs = [e.seq for e in audit_rows(app)]
    assert seqs == list(range(1, len(seqs) + 1))


def test_attacker_controlled_strings_cannot_forge_log_lines(app):
    Client(app).login("eve\n2026-01-01 audit OK admin downloaded", "x")
    ev = audit_rows(app, action="auth.login", outcome="denied")[-1]
    assert "\n" not in ev.actor_username and len(ev.actor_username) <= 64


def test_audit_trail_is_admin_only(client_for):
    for name in ("olivia", "victor"):
        assert client_for(name).get("/api/v1/admin/audit").status_code == 403
    res = client_for("admin").get("/api/v1/admin/audit?outcome=success&limit=5")
    assert res.status_code == 200 and len(res.get_json()["items"]) == 5
