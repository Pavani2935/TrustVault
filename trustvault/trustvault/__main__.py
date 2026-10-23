"""Operator CLI:  python -m trustvault <command>

  init-db                 create tables and append-only triggers
  seed-demo               create demo accounts and documents (only on an empty database)
  create-admin USERNAME   create an administrator (password from TV_BOOTSTRAP_PASSWORD or prompt)
  verify-audit            verify the audit chain; exit code 1 if tampering is detected
  purge-expired           permanently purge documents in the trash longer than TV_TRASH_RETENTION_DAYS
  generate-keys           print fresh TV_MASTER_KEY / TV_AUDIT_KEY values
  export-schema           write db/schema.sqlite.sql and db/schema.postgres.sql
  serve                   development server on 127.0.0.1:5000
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m trustvault", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    sub.add_parser("seed-demo")
    p = sub.add_parser("create-admin")
    p.add_argument("username")
    p.add_argument("--display-name", default=None)
    p = sub.add_parser("verify-audit")
    p.add_argument("--anchors", help="external anchor file (JSON lines) to compare against")
    p = sub.add_parser("purge-expired")
    p.add_argument("--days", type=int, default=None)
    sub.add_parser("generate-keys")
    sub.add_parser("export-schema")
    p = sub.add_parser("serve")
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)))
    args = parser.parse_args(argv)

    if args.cmd == "generate-keys":
        from .config import generate_key
        print(f"TV_MASTER_KEY={generate_key()}")
        print(f"TV_AUDIT_KEY={generate_key()}")
        return 0

    if args.cmd == "export-schema":
        return _export_schema()

    from . import create_app
    app = create_app()
    with app.app_context():
        from .db import get_db
        if args.cmd == "init-db":
            print("schema ready")
        elif args.cmd == "seed-demo":
            from .seed import seed_demo
            print(seed_demo())
        elif args.cmd == "create-admin":
            return _create_admin(get_db(), args.username, args.display_name)
        elif args.cmd == "verify-audit":
            from . import audit
            settings = app.config["TV_SETTINGS"]
            anchor_path = args.anchors or settings.audit_anchor_file
            external = audit.read_anchor_file(anchor_path) if anchor_path else []
            report = audit.verify_chain(get_db(), settings.audit_key, external)
            print(json.dumps(report, indent=2))
            return 0 if report["valid"] else 1
        elif args.cmd == "purge-expired":
            from .services.documents import purge_expired
            days = args.days if args.days is not None else app.config["TV_SETTINGS"].trash_retention_days
            print(f"purged {purge_expired(get_db(), days)} document(s)")
        elif args.cmd == "serve":
            app.run(host="127.0.0.1", port=args.port, debug=False)
    return 0


def _create_admin(db, username: str, display_name: str | None) -> int:
    from sqlalchemy import select

    from . import audit
    from .models import User
    from .security.passwords import hash_password, password_problems
    username = username.strip().lower()
    if db.execute(select(User).where(User.username == username)).scalar_one_or_none():
        print("username already exists", file=sys.stderr)
        return 1
    password = os.environ.get("TV_BOOTSTRAP_PASSWORD") or getpass.getpass("Password: ")
    problems = password_problems(password, username)
    if problems:
        print("password " + "; ".join(problems), file=sys.stderr)
        return 1
    user = User(username=username, display_name=display_name or username, role="admin",
                password_hash=hash_password(password), must_change_password=False)
    db.add(user)
    db.flush()
    audit.record(db, action="user.create", actor_label="system:cli", target_user_id=user.id,
                 details={"username": username, "role": "admin"})
    db.commit()
    print(f"administrator '{username}' created")
    return 0


def _export_schema() -> int:
    from sqlalchemy import create_mock_engine
    from sqlalchemy.schema import CreateIndex, CreateTable

    from .db import POSTGRES_PROTECTIONS, SQLITE_PROTECTIONS
    from .models import Base
    out_dir = Path(__file__).resolve().parent.parent / "db"
    out_dir.mkdir(exist_ok=True)
    for dialect, url, protections in (("sqlite", "sqlite://", SQLITE_PROTECTIONS),
                                      ("postgres", "postgresql+psycopg://", POSTGRES_PROTECTIONS)):
        engine = create_mock_engine(url, executor=lambda *a, **k: None)
        lines = [f"-- TrustVault schema ({dialect}). Generated by `python -m trustvault export-schema`.",
                 "-- The application creates this automatically with `python -m trustvault init-db`.", ""]
        for table in Base.metadata.sorted_tables:
            lines.append(str(CreateTable(table).compile(dialect=engine.dialect)).strip() + ";\n")
            for index in sorted(table.indexes, key=lambda i: i.name):
                lines.append(str(CreateIndex(index).compile(dialect=engine.dialect)).strip() + ";")
            lines.append("")
        lines.append("-- Append-only protection for the audit trail")
        for stmt in protections:
            lines.append(" ".join(stmt.split()) + ";")
        (out_dir / f"schema.{dialect}.sql").write_text("\n".join(lines) + "\n")
        print(f"wrote db/schema.{dialect}.sql")
    return 0


if __name__ == "__main__":
    sys.exit(main())
