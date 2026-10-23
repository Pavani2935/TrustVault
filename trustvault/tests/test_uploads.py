"""T-50..T-62: what is uploaded is validated, and stored files are unreadable without authorisation."""
from __future__ import annotations

import io
import json
import zipfile

import pytest
from sqlalchemy import select

from conftest import audit_rows, raw_sql


def office(kind="word", extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(f"{kind}/document.xml", "<doc/>")
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


def upload(c, data, name, title="Test upload", category="Testing"):
    return c.post("/api/v1/documents", data={"title": title, "category": category, "file": (io.BytesIO(data), name)},
                  content_type="multipart/form-data")


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


@pytest.mark.parametrize("data,name,reason", [
    (b"MZ\x90\x00 executable", "invoice.pdf", "does not match"),
    (b"MZ\x90\x00 executable", "tool.exe", "not allowed"),
    (b"<html><script>alert(1)</script></html>", "page.txt", "HTML"),
    (b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>", "logo.txt", "HTML"),
    (b"<html></html>", "page.html", "not allowed"),
    (PNG, "photo.pdf", "does not match"),
    (b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>", "x.pdf", "JavaScript"),
    (b"%PDF-1.7\n1 0 obj << /Launch /F (cmd.exe) >>", "x.pdf", "JavaScript"),
    (office(extra={"word/vbaProject.bin": b"macro"}), "report.docx", "macro"),
    (office(), "report.docm", "not allowed"),
    (b"PK\x03\x04" + b"\x00" * 30, "archive.docx", "damaged"),
    (b"", "empty.txt", "empty"),
    (b"\xff\xfe\x00b\x00i\x00n", "data.txt", "binary"),
    (b"hello", ".htaccess", "not allowed"),
])
def test_dangerous_or_mismatched_files_are_refused(app, client_for, data, name, reason):
    res = upload(client_for("olivia"), data, name)
    assert res.status_code == 400, res.get_data(as_text=True)
    assert reason.lower() in res.get_json()["error"]["message"].lower()
    ev = audit_rows(app, action="document.create", outcome="denied")[-1]
    assert json.loads(ev.details)["reason"] == "validation failed"


def test_plain_zip_is_refused(client_for):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "hi")
    assert upload(client_for("olivia"), buf.getvalue(), "bundle.docx").status_code == 400


def test_zip_bomb_ratio_is_refused(client_for):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "A" * 5_000_000)
    assert upload(client_for("olivia"), buf.getvalue(), "big.docx").status_code == 400


@pytest.mark.parametrize("data,name", [
    (PNG, "photo.png"), (b"\xff\xd8\xff\xe0" + b"\x00" * 32, "scan.jpg"), (office(), "letter.docx"),
    (office("xl"), "budget.xlsx"), (office("ppt"), "deck.pptx"), (b"a,b\n1,2\n", "data.csv"),
    ("Résumé – naïve café\n".encode(), "notes.txt"),
])
def test_legitimate_files_are_accepted(client_for, data, name):
    res = upload(client_for("olivia"), data, name)
    assert res.status_code == 201, res.get_data(as_text=True)


def test_file_names_are_sanitised(client_for):
    c = client_for("olivia")
    res = upload(c, b"x", "../../etc/passwd.txt")
    assert res.get_json()["latest_version"]["filename"] == "passwd.txt"
    res = upload(c, b"x", "C:\\Users\\me\\report\u202etxt.exe.txt")
    name = res.get_json()["latest_version"]["filename"]
    assert "\u202e" not in name and "\\" not in name and name.endswith(".txt")


def test_text_fields_are_validated(client_for):
    c = client_for("olivia")
    assert upload(c, b"x", "a.txt", title="").status_code == 400
    assert upload(c, b"x", "a.txt", title="t" * 161).status_code == 400
    assert upload(c, b"x", "a.txt", category="<script>").status_code == 400
    res = upload(c, b"x", "a.txt", title="<img src=x onerror=alert(1)>")
    # Stored as text (the UI renders with textContent); never interpreted server-side.
    assert res.status_code == 201 and res.get_json()["title"] == "<img src=x onerror=alert(1)>"


def test_oversized_upload_is_refused(make):
    from conftest import Client
    app = make(max_upload_bytes=1024)
    c = Client(app)
    c.login("olivia")
    assert upload(c, b"a" * 1025, "big.txt").status_code == 400
    assert upload(c, b"a" * 4096, "bigger.txt").status_code in (400, 413)
    assert upload(c, b"a" * 1024, "ok.txt").status_code == 201


def test_files_are_encrypted_at_rest(app, ids):
    rows = raw_sql(app, "SELECT ciphertext FROM blobs")
    assert rows and all(b"sample" not in bytes(r[0]).lower() and b"CONFIDENTIAL" not in bytes(r[0]) for r in rows)
    wrapped = raw_sql(app, "SELECT wrapped_key FROM document_versions")
    assert all(len(bytes(r[0])) == 12 + 32 + 16 for r in wrapped)


def test_swapped_ciphertext_is_detected_not_served(app, ids, client_for):
    """A database-level attacker moves another document's ciphertext under a document
    they can read. The associated data binds ciphertext to its document, so it fails."""
    from trustvault.db import get_db
    from trustvault.models import DocumentVersion
    with app.app_context():
        db = get_db()
        offer = db.execute(select(DocumentVersion).where(DocumentVersion.document_id == ids["docs"]["offer"])).scalar_one()
        board = db.execute(select(DocumentVersion).where(DocumentVersion.document_id == ids["docs"]["board"])).scalar_one()
        offer_blob, board_blob = offer.blob_id, board.blob_id
    raw_sql(app, "UPDATE blobs SET ciphertext = (SELECT ciphertext FROM blobs WHERE id = :b) WHERE id = :o",
            b=board_blob, o=offer_blob)
    res = client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    assert res.status_code == 500
    assert b"BOARD" not in res.data
    assert audit_rows(app, action="document.download", outcome="error")


def test_download_returns_exact_bytes_and_hash(ids, client_for):
    import hashlib
    res = client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    assert res.data.startswith(b"%PDF-")
    assert hashlib.sha256(res.data).hexdigest() == res.headers["X-Content-SHA256"]


def test_tampered_hash_metadata_is_detected_not_served(app, ids, client_for):
    """Found by scripts/mutation_check.py: the SHA-256 re-check after decryption was untested.
    GCM proves the bytes are intact; the stored hash is what the audit trail and the
    X-Content-SHA256 header promise. If someone edits it in the database, refuse and record."""
    raw_sql(app, "UPDATE document_versions SET sha256 = :h WHERE document_id = :d",
            h="0" * 64, d=ids["docs"]["offer"])
    res = client_for("victor").get(f"/api/v1/documents/{ids['docs']['offer']}/download")
    assert res.status_code == 500 and res.get_json()["error"]["code"] == "integrity_error"
    ev = audit_rows(app, action="document.download", outcome="error")[-1]
    assert json.loads(ev.details)["reason"] == "sha256 mismatch"
