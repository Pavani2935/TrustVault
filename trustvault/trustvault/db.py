"""Engine, per-request sessions and database-level protections."""
from __future__ import annotations

from flask import current_app, g
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

# Database-level enforcement of "append-only". The application never issues UPDATE
# or DELETE against audit tables; these triggers make the database refuse them too,
# so a bug, an SQL injection or a careless operator cannot silently rewrite history.
SQLITE_PROTECTIONS = [
    """CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
       BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_checkpoints_no_update BEFORE UPDATE ON audit_checkpoints
       BEGIN SELECT RAISE(ABORT, 'audit_checkpoints is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_checkpoints_no_delete BEFORE DELETE ON audit_checkpoints
       BEGIN SELECT RAISE(ABORT, 'audit_checkpoints is append-only'); END""",
]

POSTGRES_PROTECTIONS = [
    """CREATE OR REPLACE FUNCTION tv_append_only() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END; $$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events",
    """CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
       FOR EACH ROW EXECUTE FUNCTION tv_append_only()""",
    "DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events",
    """CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
       FOR EACH STATEMENT EXECUTE FUNCTION tv_append_only()""",
    "DROP TRIGGER IF EXISTS audit_checkpoints_append_only ON audit_checkpoints",
    """CREATE TRIGGER audit_checkpoints_append_only BEFORE UPDATE OR DELETE ON audit_checkpoints
       FOR EACH ROW EXECUTE FUNCTION tv_append_only()""",
    "DROP TRIGGER IF EXISTS audit_checkpoints_no_truncate ON audit_checkpoints",
    """CREATE TRIGGER audit_checkpoints_no_truncate BEFORE TRUNCATE ON audit_checkpoints
       FOR EACH STATEMENT EXECUTE FUNCTION tv_append_only()""",
]


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})

        @event.listens_for(engine, "connect")
        def _sqlite_connect(dbapi_conn, _record):
            # Take over transaction control from pysqlite so we can use BEGIN IMMEDIATE.
            dbapi_conn.isolation_level = None
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.close()

        @event.listens_for(engine, "begin")
        def _sqlite_begin(conn):
            # Serialises writers so two requests can never read the same audit head.
            conn.exec_driver_sql("BEGIN IMMEDIATE")

        return engine
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)


def create_schema(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    statements = POSTGRES_PROTECTIONS if engine.dialect.name == "postgresql" else SQLITE_PROTECTIONS
    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))


def get_db() -> Session:
    if "db" not in g:
        g.db = current_app.extensions["tv_sessionmaker"]()
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        if db.in_transaction():
            db.rollback()
        db.close()


def init_app(app, engine: Engine) -> None:
    app.extensions["tv_engine"] = engine
    app.extensions["tv_sessionmaker"] = sessionmaker(bind=engine, expire_on_commit=False)
    app.teardown_appcontext(close_db)
