"""Test fixtures.

Every test gets a fresh database seeded with the demo data (5 people, 7 documents,
5 grants). Set TV_TEST_DATABASE_URL to a PostgreSQL URL to run the same suite against
PostgreSQL; otherwise a temporary SQLite file is used.

Ground truth used throughout (see trustvault/seed.py):
  olivia (owner): Offer letter      -> victor:read
                  Salary revision   -> nobody
                  MSA Acme          -> vera:read
                  Cleanroom layout  -> vera:edit
  oscar (owner):  Q2 audit papers   -> vera:read, olivia:read
                  Board minutes     -> nobody
                  Q3 sampling plan  -> nobody
  admin: no grants.  victor, vera: viewers.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("TV_FAST_PASSWORD_HASHING", "1")  # cheap Argon2 parameters for tests only

from trustvault import create_app  # noqa: E402
from trustvault.config import generate_key  # noqa: E402

PASSWORDS = {
    "admin": "Admin#Vault2026", "olivia": "Owner#Vault2026", "oscar": "Owner2#Vault2026",
    "victor": "Viewer#Vault2026", "vera": "Viewer2#Vault2026",
}
TITLES = {
    "offer": "Offer letter - Victor Das",
    "salary": "Salary revision 2026 - all staff",
    "msa": "Master services agreement - Acme Pharma",
    "drawing": "Cleanroom layout - Block C rev 3",
    "q2": "Q2 audit working papers",
    "board": "Board minutes - restructuring (restricted)",
    "q3": "Q3 audit sampling plan",
}
# (document key) -> {username: effective permission}
TRUTH = {
    "offer": {"olivia": "owner", "victor": "read"},
    "salary": {"olivia": "owner"},
    "msa": {"olivia": "owner", "vera": "read"},
    "drawing": {"olivia": "owner", "vera": "edit"},
    "q2": {"oscar": "owner", "vera": "read", "olivia": "read"},
    "board": {"oscar": "owner"},
    "q3": {"oscar": "owner"},
}
USERS = list(PASSWORDS)


def _reset_postgres(url: str) -> None:
    engine = create_engine(url.replace("postgresql://", "postgresql+psycopg://", 1) if url.startswith("postgresql://") else url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


def make_app(tmp_path, **overrides):
    url = os.environ.get("TV_TEST_DATABASE_URL")
    if url:
        _reset_postgres(url)
    else:
        url = f"sqlite:///{tmp_path / 'test.db'}"
    settings = {"env": "test", "database_url": url, "master_key": generate_key(), "audit_key": generate_key(),
                "cookie_secure": False, "demo_mode": False}
    settings.update(overrides)
    app = create_app(settings)
    with app.app_context():
        from trustvault.seed import seed_demo
        seed_demo()
    return app


@pytest.fixture()
def app(tmp_path):
    app = make_app(tmp_path)
    yield app
    app.extensions["tv_engine"].dispose()


@pytest.fixture()
def make(tmp_path):
    """Factory for an app with non-default settings, e.g. make(demo_mode=True)."""
    created = []

    def factory(**overrides):
        sub = tmp_path / f"app{len(created)}"
        sub.mkdir()
        a = make_app(sub, **overrides)
        created.append(a)
        return a
    yield factory
    for a in created:
        a.extensions["tv_engine"].dispose()


class Client:
    """Test client that behaves like the real browser UI: it sends the CSRF header."""

    def __init__(self, app):
        self.app = app
        self.http = app.test_client()
        self.csrf = None
        self.username = None

    def login(self, username, password=None):
        res = self.http.post("/api/v1/auth/login", json={"username": username, "password": password or PASSWORDS[username]})
        if res.status_code == 200:
            self.csrf = res.get_json()["csrf_token"]
            self.username = username
        return res

    def _headers(self, extra=None):
        h = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        h.update(extra or {})
        return h

    def get(self, path, **kw):
        return self.http.get(path, headers=self._headers(kw.pop("headers", None)), **kw)

    def head(self, path, **kw):
        return self.http.head(path, headers=self._headers(kw.pop("headers", None)), **kw)

    def post(self, path, **kw):
        return self.http.post(path, headers=self._headers(kw.pop("headers", None)), **kw)

    def put(self, path, **kw):
        return self.http.put(path, headers=self._headers(kw.pop("headers", None)), **kw)

    def patch(self, path, **kw):
        return self.http.patch(path, headers=self._headers(kw.pop("headers", None)), **kw)

    def delete(self, path, **kw):
        return self.http.delete(path, headers=self._headers(kw.pop("headers", None)), **kw)

    def session_cookie(self):
        name = self.app.config["TV_SETTINGS"].session_cookie_name
        c = self.http.get_cookie(name)
        return c.value if c else None


@pytest.fixture()
def client_for(app):
    cache = {}

    def factory(username):
        if username not in cache:
            c = Client(app)
            assert c.login(username).status_code == 200, f"login failed for {username}"
            cache[username] = c
        return cache[username]
    return factory


@pytest.fixture()
def ids(app):
    from trustvault.db import get_db
    from trustvault.models import Document, User
    with app.app_context():
        db = get_db()
        users = {u.username: u.id for u in db.execute(select(User)).scalars()}
        by_title = {d.title: d.id for d in db.execute(select(Document)).unique().scalars()}
    docs = {key: by_title[title] for key, title in TITLES.items()}
    return {"users": users, "docs": docs}


def audit_rows(app, **filters):
    from trustvault.db import get_db
    from trustvault.models import AuditEvent
    with app.app_context():
        stmt = select(AuditEvent).order_by(AuditEvent.seq)
        for k, v in filters.items():
            stmt = stmt.where(getattr(AuditEvent, k) == v)
        db = get_db()
        rows = db.execute(stmt).scalars().all()
        db.expunge_all()
        return rows


def raw_sql(app, sql, **params):
    """Run SQL directly against the database, bypassing the application (simulates a DB-level attacker)."""
    engine = app.extensions["tv_engine"]
    with engine.connect() as conn:
        result = conn.execute(text(sql), params)
        rows = result.fetchall() if result.returns_rows else None
        conn.commit()
        return rows


def is_postgres(app) -> bool:
    return app.extensions["tv_engine"].dialect.name == "postgresql"
