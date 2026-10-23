"""TrustVault: secure document sharing with a verifiable audit trail."""
from __future__ import annotations

import logging
import sys
import uuid
from pathlib import Path

from flask import Flask, g, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db as dbmod
from . import errors
from .config import load_settings

STATIC_DIR = Path(__file__).resolve().parent / "web"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; "
    "frame-ancestors 'none'; object-src 'none'"
)


def _configure_logging() -> None:
    root = logging.getLogger("trustvault")
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.INFO)
        root.propagate = False


def create_app(overrides: dict | None = None, *, create_tables: bool = True) -> Flask:
    _configure_logging()
    settings = load_settings(overrides)
    if settings.env == "test":
        logging.getLogger("trustvault.audit").setLevel(logging.WARNING)
        logging.getLogger("trustvault.audit.anchor").setLevel(logging.ERROR)
    app = Flask(__name__, static_folder=None)
    app.json.sort_keys = False  # keep the field order the API documents
    app.config.update(
        TV_SETTINGS=settings,
        MAX_CONTENT_LENGTH=settings.max_upload_bytes + 512 * 1024,  # file + multipart overhead
        TESTING=settings.env == "test",
    )
    if settings.trusted_proxies:
        # Only trust X-Forwarded-* from the number of proxies we actually sit behind;
        # otherwise a client could spoof its IP and dodge login throttling.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=settings.trusted_proxies, x_proto=settings.trusted_proxies)

    engine = dbmod.make_engine(settings.database_url)
    dbmod.init_app(app, engine)
    if create_tables:
        dbmod.create_schema(engine)

    errors.register(app)

    from .api import bp as api_bp
    app.register_blueprint(api_bp)

    @app.before_request
    def _request_id():
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def _security_headers(resp):
        h = resp.headers
        h.setdefault("Content-Security-Policy", CSP)  # downloads set a stricter sandbox CSP
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        h["X-Request-Id"] = getattr(g, "request_id", "")
        if settings.cookie_secure:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            # Nothing the API returns may be kept by the browser or a proxy. Above all a
            # downloaded file must not be re-openable from cache after access is revoked.
            h["Cache-Control"] = "no-store"
            h["Pragma"] = "no-cache"
        h.pop("Server", None)
        return resp

    @app.get("/")
    def _index():
        return send_from_directory(STATIC_DIR, "index.html", max_age=0)

    @app.get("/assets/<path:name>")
    def _assets(name: str):
        return send_from_directory(STATIC_DIR / "assets", name, max_age=300)

    @app.get("/healthz")
    def _health():
        return {"status": "ok"}

    return app
