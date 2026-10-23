"""T-70..T-85: browser-level attacks: CSRF, cross-origin, XSS sinks, clickjacking, cookies,
enumeration and brute force."""
from __future__ import annotations

import hashlib

from conftest import Client, audit_rows, raw_sql


def test_state_change_without_csrf_token_is_refused(ids, client_for):
    olivia = client_for("olivia")
    doc, victim = ids["docs"]["salary"], ids["users"]["victor"]
    no_token = olivia.http.put(f"/api/v1/documents/{doc}/grants/{victim}", json={"permission": "read"})
    assert no_token.status_code == 403 and no_token.get_json()["error"]["code"] == "csrf"
    bad = olivia.http.put(f"/api/v1/documents/{doc}/grants/{victim}", json={"permission": "read"},
                          headers={"X-CSRF-Token": "guess"})
    assert bad.status_code == 403
    assert client_for("victor").get(f"/api/v1/documents/{doc}").status_code == 404


def test_csrf_token_of_another_session_is_useless(app, ids, client_for):
    olivia, victor = client_for("olivia"), client_for("victor")
    res = olivia.http.delete(f"/api/v1/documents/{ids['docs']['salary']}", headers={"X-CSRF-Token": victor.csrf})
    assert res.status_code == 403


def test_cross_origin_requests_are_refused(ids, client_for):
    olivia = client_for("olivia")
    res = olivia.delete(f"/api/v1/documents/{ids['docs']['salary']}", headers={"Origin": "https://evil.example"})
    assert res.status_code == 403 and res.get_json()["error"]["code"] == "bad_origin"
    res = olivia.delete(f"/api/v1/documents/{ids['docs']['salary']}", headers={"Origin": "null"})
    assert res.status_code == 403


def test_login_requires_json_so_html_forms_cannot_post_it(app):
    res = app.test_client().post("/api/v1/auth/login", data={"username": "olivia", "password": "Owner#Vault2026"})
    assert res.status_code == 415


def test_session_cookie_flags(app):
    res = Client(app).login("victor")
    cookie = res.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie


def test_secure_cookie_uses_host_prefix(make):
    app = make(cookie_secure=True)
    res = app.test_client().post("/api/v1/auth/login", json={"username": "victor", "password": "Viewer#Vault2026"},
                                 base_url="https://localhost")
    cookie = res.headers["Set-Cookie"]
    assert cookie.startswith("__Host-tv_session=") and "Secure" in cookie
    assert "Strict-Transport-Security" in res.headers


def test_session_token_is_stored_hashed(app, client_for):
    token = client_for("victor").session_cookie()
    stored = [r[0] for r in raw_sql(app, "SELECT token_hash FROM sessions")]
    assert token not in stored
    assert hashlib.sha256(token.encode()).hexdigest() in stored


def test_security_headers_everywhere(app, client_for):
    for res in (app.test_client().get("/"), client_for("victor").get("/api/v1/documents")):
        h = res.headers
        assert "script-src 'self'" in h["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert h["Referrer-Policy"] == "no-referrer"


def test_downloads_are_sandboxed_attachments(ids, client_for):
    res = client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    assert res.headers["Content-Security-Policy"].startswith("sandbox")
    assert "attachment" in res.headers["Content-Disposition"]


def test_login_errors_do_not_reveal_whether_an_account_exists(app):
    wrong_pw = Client(app).login("olivia", "Wrong#Password1")
    no_user = Client(app).login("no-such-person", "Wrong#Password1")
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.get_json()["error"]["message"] == no_user.get_json()["error"]["message"]


def test_deactivated_account_gets_the_same_login_error(app, ids, client_for):
    client_for("admin").patch(f"/api/v1/admin/users/{ids['users']['victor']}", json={"is_active": False})
    res = Client(app).login("victor")
    assert res.status_code == 401
    assert res.get_json()["error"]["message"] == "Sign-in failed. Check your username and password."


def test_brute_force_is_throttled_per_account_and_ip(app):
    for _ in range(5):
        assert Client(app).login("olivia", "Wrong#Password1").status_code == 401
    assert Client(app).login("olivia", "Wrong#Password1").status_code == 429
    # Even the right password is refused while throttled (no oracle).
    assert Client(app).login("olivia").status_code == 429
    # Other accounts from the same IP are not locked by this.
    assert Client(app).login("oscar").status_code == 200
    assert any("throttled" in e.details for e in audit_rows(app, action="auth.login", outcome="denied"))


def test_password_policy_is_enforced(ids, client_for):
    admin = client_for("admin")
    for weak in ("short", "alllowercaseletters", "password1234", "newperson-Abc1!"):
        res = admin.post("/api/v1/admin/users", json={"username": "newperson", "role": "viewer", "password": weak})
        assert res.status_code == 400


def test_unknown_json_fields_are_rejected(client_for):
    res = client_for("admin").post("/api/v1/admin/users", json={
        "username": "mallory", "role": "viewer", "password": "Str0ng#Password", "is_active": True, "id": "x"})
    assert res.status_code == 400


def test_errors_do_not_leak_internals(app, client_for):
    res = client_for("victor").get("/api/v1/documents?from=not-a-date")
    body = res.get_data(as_text=True)
    assert res.status_code == 400 and "Traceback" not in body and "sqlalchemy" not in body.lower()
    res = client_for("victor").get("/api/v1/documents?sort=password_hash")
    assert res.status_code == 400
