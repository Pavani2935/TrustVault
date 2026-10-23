from __future__ import annotations

from urllib.parse import quote

from flask import Response, current_app, g, jsonify, request

from ..db import get_db
from ..errors import ApiError
from ..services import documents as docs
from ..services import sharing
from ..validation import ValidationError
from . import bp, json_body, login_required, roles_required


def _read_upload() -> tuple[str, bytes]:
    f = request.files.get("file")
    if f is None or not f.filename:
        raise ValidationError("a file is required", "file")
    limit = current_app.config["TV_SETTINGS"].max_upload_bytes
    data = f.stream.read(limit + 1)
    return f.filename, data


@bp.get("/documents")
@login_required
def list_documents():
    return jsonify(docs.search(get_db(), g.user, request.args))


@bp.get("/categories")
@login_required
def list_categories():
    return jsonify({"items": docs.categories(get_db(), g.user)})


@bp.post("/documents")
@login_required
def create_document():
    filename, data = _read_upload()
    doc = docs.create_document(get_db(), g.user, title=request.form.get("title"),
                               category=request.form.get("category"), filename=filename, data=data)
    return jsonify(docs.document_json(doc, "owner", with_versions=True)), 201


@bp.get("/documents/trash")
@roles_required("owner")
def list_trash():
    return jsonify({"items": docs.trash(get_db(), g.user)})


@bp.get("/documents/<doc_id>")
@login_required
def get_document(doc_id):
    return jsonify(docs.view(get_db(), g.user, doc_id))


@bp.patch("/documents/<doc_id>")
@login_required
def patch_document(doc_id):
    body = json_body({"title", "category"})
    doc = docs.update_metadata(get_db(), g.user, doc_id, body)
    return jsonify({"id": doc.id, "title": doc.title, "category": doc.category})


@bp.post("/documents/<doc_id>/versions")
@login_required
def upload_version(doc_id):
    filename, data = _read_upload()
    version = docs.add_version(get_db(), g.user, doc_id, filename=filename, data=data)
    return jsonify(docs.version_json(version)), 201


@bp.get("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    data, version = docs.download(get_db(), g.user, doc_id, request.args.get("version"), method=request.method)
    filename = version.original_filename
    ascii_name = filename.encode("ascii", "ignore").decode().replace('"', "") or "download"
    resp = Response(data, status=200, mimetype="application/octet-stream")
    # Always an attachment, never rendered inline by the browser; sandboxed if it ever is.
    resp.headers["Content-Disposition"] = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"
    resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    resp.headers["X-Content-SHA256"] = version.sha256
    return resp


@bp.delete("/documents/<doc_id>")
@login_required
def delete_document(doc_id):
    docs.delete(get_db(), g.user, doc_id)
    return jsonify({"ok": True, "status": "in_trash"})


@bp.post("/documents/<doc_id>/restore")
@login_required
def restore_document(doc_id):
    doc = docs.restore(get_db(), g.user, doc_id)
    return jsonify({"ok": True, "id": doc.id})


@bp.delete("/documents/<doc_id>/purge")
@login_required
def purge_document(doc_id):
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != "PURGE":
        raise ApiError(400, "confirmation_required", 'Send {"confirm": "PURGE"} to permanently destroy this document.')
    docs.purge(get_db(), g.user, doc_id)
    return jsonify({"ok": True, "status": "purged"})


@bp.get("/documents/<doc_id>/activity")
@login_required
def document_activity(doc_id):
    return jsonify({"items": docs.activity(get_db(), g.user, doc_id)})


# --- grants ---------------------------------------------------------------------------------

@bp.get("/documents/<doc_id>/grants")
@login_required
def list_grants(doc_id):
    return jsonify({"items": sharing.list_grants(get_db(), g.user, doc_id)})


@bp.put("/documents/<doc_id>/grants/<user_id>")
@login_required
def put_grant(doc_id, user_id):
    body = json_body({"permission", "source"}, {"permission"})
    return jsonify(sharing.set_grant(get_db(), g.user, doc_id, user_id, body))


@bp.delete("/documents/<doc_id>/grants/<user_id>")
@login_required
def delete_grant(doc_id, user_id):
    sharing.revoke_grant(get_db(), g.user, doc_id, user_id)
    return jsonify({"ok": True})


# --- suggestions ----------------------------------------------------------------------------

@bp.get("/documents/<doc_id>/suggestions")
@login_required
def get_suggestions(doc_id):
    return jsonify({"items": sharing.suggestions(get_db(), g.user, doc_id),
                    "note": "Suggestions never grant access. Confirm each one explicitly."})


@bp.post("/documents/<doc_id>/suggestions/<user_id>/dismiss")
@login_required
def dismiss_suggestion(doc_id, user_id):
    sharing.dismiss_suggestion(get_db(), g.user, doc_id, user_id)
    return jsonify({"ok": True})
