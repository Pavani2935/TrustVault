"""Runtime configuration.

Every setting comes from the environment. In production the application refuses
to start if a secret is missing or obviously weak: a default secret that silently
"works" is how a demo key ends up protecting real data.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass, field, replace
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return default if raw in (None, "") else int(raw)


def _decode_key(name: str, value: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(value.strip() + "=" * (-len(value.strip()) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(f"{name} is not valid base64") from exc
    if len(key) != 32:
        raise ConfigError(f"{name} must decode to exactly 32 bytes (got {len(key)})")
    return key


def generate_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


@dataclass(frozen=True)
class Settings:
    env: str
    database_url: str
    master_key: bytes          # wraps per-file data keys (envelope encryption)
    audit_key: bytes           # HMAC key for the audit chain; deliberately different from master_key
    cookie_secure: bool
    trusted_proxies: int
    session_idle_minutes: int
    session_absolute_hours: int
    max_upload_bytes: int
    trash_retention_days: int
    demo_mode: bool
    audit_checkpoint_every: int
    audit_anchor_file: str | None
    login_max_failures_per_user_ip: int
    login_max_failures_per_ip: int
    login_window_minutes: int
    alert_thresholds: dict = field(default_factory=dict)

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def session_cookie_name(self) -> str:
        # The __Host- prefix makes the browser refuse the cookie unless it is
        # Secure, has Path=/ and no Domain, which blocks subdomain cookie injection.
        return "__Host-tv_session" if self.cookie_secure else "tv_session"


def _dev_keys(instance_dir: Path) -> tuple[str, str]:
    """Development only: persist generated keys so restarts can still decrypt files."""
    instance_dir.mkdir(parents=True, exist_ok=True)
    path = instance_dir / "dev-keys.json"
    if path.exists():
        data = json.loads(path.read_text())
    else:
        data = {"master": generate_key(), "audit": generate_key()}
        path.write_text(json.dumps(data))
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return data["master"], data["audit"]


def load_settings(overrides: dict | None = None) -> Settings:
    overrides = overrides or {}
    env = overrides.get("env") or os.environ.get("TV_ENV", "development")
    if env not in {"development", "production", "test"}:
        raise ConfigError("TV_ENV must be development, production or test")

    root = Path(__file__).resolve().parent.parent
    instance_dir = Path(os.environ.get("TV_INSTANCE_DIR", root / "instance"))
    default_db = f"sqlite:///{(instance_dir / 'trustvault.db').as_posix()}"
    database_url = overrides.get("database_url") or os.environ.get("TV_DATABASE_URL") or os.environ.get("DATABASE_URL") or default_db
    # Hosting providers often hand out postgres:// URLs; SQLAlchemy needs an explicit driver.
    if database_url.startswith("postgres://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
    elif database_url.startswith("postgresql://"):
        database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]

    master_raw = overrides.get("master_key") or os.environ.get("TV_MASTER_KEY")
    audit_raw = overrides.get("audit_key") or os.environ.get("TV_AUDIT_KEY")
    if env == "production":
        if not master_raw or not audit_raw:
            raise ConfigError("TV_MASTER_KEY and TV_AUDIT_KEY are required in production")
        if database_url.startswith("sqlite") and not _bool("TV_ALLOW_SQLITE_IN_PRODUCTION", False):
            raise ConfigError("Use PostgreSQL in production (or set TV_ALLOW_SQLITE_IN_PRODUCTION=true knowingly)")
    elif not master_raw or not audit_raw:
        dev_master, dev_audit = _dev_keys(instance_dir)
        master_raw = master_raw or dev_master
        audit_raw = audit_raw or dev_audit

    master_key = _decode_key("TV_MASTER_KEY", master_raw)
    audit_key = _decode_key("TV_AUDIT_KEY", audit_raw)
    if master_key == audit_key:
        raise ConfigError("TV_MASTER_KEY and TV_AUDIT_KEY must be different keys")

    if database_url.startswith("sqlite:///"):
        Path(database_url[len("sqlite:///"):]).parent.mkdir(parents=True, exist_ok=True)

    settings = Settings(
        env=env,
        database_url=database_url,
        master_key=master_key,
        audit_key=audit_key,
        cookie_secure=overrides.get("cookie_secure", _bool("TV_COOKIE_SECURE", env == "production")),
        trusted_proxies=_int("TV_TRUSTED_PROXIES", 0),
        session_idle_minutes=_int("TV_SESSION_IDLE_MINUTES", 30),
        session_absolute_hours=_int("TV_SESSION_ABSOLUTE_HOURS", 8),
        max_upload_bytes=_int("TV_MAX_UPLOAD_MB", 10) * 1024 * 1024,
        trash_retention_days=_int("TV_TRASH_RETENTION_DAYS", 30),
        demo_mode=overrides.get("demo_mode", _bool("TV_DEMO_MODE", False)),
        audit_checkpoint_every=_int("TV_AUDIT_CHECKPOINT_EVERY", 50),
        audit_anchor_file=os.environ.get("TV_AUDIT_ANCHOR_FILE") or None,
        login_max_failures_per_user_ip=_int("TV_LOGIN_MAX_FAILURES_PER_USER_IP", 5),
        login_max_failures_per_ip=_int("TV_LOGIN_MAX_FAILURES_PER_IP", 30),
        login_window_minutes=_int("TV_LOGIN_WINDOW_MINUTES", 15),
        alert_thresholds={
            "denied_per_hour": _int("TV_ALERT_DENIED_PER_HOUR", 5),
            "downloads_per_hour": _int("TV_ALERT_DOWNLOADS_PER_HOUR", 20),
            "grant_changes_per_hour": _int("TV_ALERT_GRANT_CHANGES_PER_HOUR", 15),
            "login_failures_per_hour": _int("TV_ALERT_LOGIN_FAILURES_PER_HOUR", 5),
        },
    )
    # Programmatic overrides (used by tests) for any remaining plain setting.
    handled = {"env", "database_url", "master_key", "audit_key", "cookie_secure", "demo_mode"}
    extra = {k: v for k, v in overrides.items() if k not in handled and k in Settings.__dataclass_fields__}
    return replace(settings, **extra) if extra else settings
