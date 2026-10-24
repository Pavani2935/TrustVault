# TrustVault — Project Documentation

## 1. Overview

TrustVault is a secure document-sharing web application designed to enforce access at the individual-document level and maintain evidence of activity. Its core security objective is that a user's role alone never grants access to every document: access depends on document ownership and an explicit grant.

- **Repository:** https://github.com/Pavani2935/TrustVault
- **Application directory:** `trustvault/`
- **Primary stack:** Python 3.11+, Flask, PostgreSQL in production, SQLite for local development, vanilla JavaScript, Docker, and Render.

## 2. Problem and goals

Ordinary folder sharing and long-lived links can expose more information than intended and make revocation difficult to prove. TrustVault is designed to address this by:

- Enforcing server-side authorization on each document request.
- Supporting named-person grants with `read` and `edit` permissions.
- Applying revocation and account changes on the next request.
- Recording successful actions and refused access attempts in an integrity-protected audit trail.
- Encrypting document versions at rest.
- Validating uploaded file content instead of trusting a filename or browser-supplied MIME type.

## 3. Roles and permissions

| Role | Main capabilities |
|---|---|
| Administrator | Manage user accounts, inspect activity and alerts, review/verify the audit trail. Administrators do not automatically gain access to document contents. |
| Document owner | Upload and manage owned documents; grant, change, or revoke named users' access; inspect document activity. |
| Viewer / recipient | Access only documents explicitly shared with them. A read grant allows viewing and downloading; an edit grant also permits supported edits such as renaming and uploading a new version. |

The owner is responsible for granting document access. There are no anonymous public links or inherited folder permissions described by the application design.

## 4. Main features

- **Document-level access control:** authorization is checked for each requested document.
- **Immediate revocation:** grants, user status, roles, password resets, and sessions are checked server-side rather than relying on long-lived signed download links.
- **Audit trail:** logs logins, views, downloads, uploads, edits, deletions, grants, revocations, and denied attempts.
- **Tamper evidence:** audit records are hash-chained with HMAC protection, sequence checks, and database protections against ordinary update/delete operations; verification is available to administrators.
- **Encrypted files:** each file version uses AES-256-GCM encryption; the data-encryption key is wrapped using a master key supplied through the environment.
- **Upload validation:** supported formats include PDF, non-macro Office documents, images, text, and CSV. Unsafe or unsupported content is rejected.
- **Search:** searches are limited to documents the current user is authorized to access.
- **Version and lifecycle controls:** document versions, trash, restore, and purge are supported; trash retention is configurable.
- **Security monitoring:** activity alerts cover patterns such as repeated denied requests, bulk downloads, brute-force attempts, integrity failures, and selected administrative events.
- **Explainable access suggestions:** suggestions can help owners review access decisions but do not grant access automatically.

## 5. Architecture

```text
Browser (vanilla JavaScript)
  | same-origin JSON requests; secure session cookie; CSRF token
  v
Flask API (/api/v1/*)
  | session, Origin and CSRF checks
  v
Application services
  | document loading -> central policy decision
  | audit record written with the action transaction
  | encryption/decryption services
  v
Database
  | PostgreSQL in production
  | SQLite for local development
```

### Authorization path

The central policy decision is implemented in `trustvault/security/policy.py::decide()`. Document operations use `trustvault/services/documents.py::load_document()` before accessing a document version, blob, or key. Keep authorization centralized and do not add download or preview paths that bypass this check.

### Security controls

- HTTP-only, SameSite-strict session cookies; production cookie security is configurable.
- Origin and CSRF checks for browser requests.
- Content Security Policy and safe DOM rendering practices in the browser UI.
- No-store caching for downloads.
- Rate limiting for authentication attempts.
- File content validation and sanitization.
- Separate environment-managed keys for file encryption and audit integrity.

These controls reduce risk but do not, by themselves, constitute a guarantee that any deployment is secure. Review configuration, secrets, infrastructure, and test results before handling real confidential data.

## 6. Repository layout

The application is contained in `trustvault/`:

```text
trustvault/
├── trustvault/             # Python application package
│   ├── api/                # HTTP/API routes
│   ├── security/           # Policy and security-related logic
│   ├── services/           # Document and application services
│   ├── __init__.py         # Application/package setup
│   ├── __main__.py         # CLI entry point
│   ├── audit.py            # Audit trail logic
│   ├── config.py           # Environment-backed configuration
│   ├── db.py               # Database connection/schema support
│   ├── models.py           # Data models
│   ├── seed.py             # Demo data
│   └── validation.py       # Input and upload validation
├── docs/
│   ├── API.md              # API reference
│   ├── DEMO_SCRIPT.md      # Demonstration walkthrough
│   ├── DEPLOY.md           # Deployment instructions
│   └── PROJECT_DOCUMENTATION.md
├── db/                     # Database schema files
├── scripts/                # Maintenance/security scripts
├── tests/                  # Automated tests
├── Dockerfile
├── docker-compose.yml
├── render.yaml
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── README.md
├── THREATS.md
├── PROMPTS.md
└── WRITEUP.md
```

## 7. Prerequisites

- Python 3.11 or newer.
- Git.
- Docker and Docker Compose for the production-like local setup.
- PostgreSQL for production-like testing; SQLite is used for a quick local run.

## 8. Run locally

Run commands from the application directory, not the repository root:

```bash
git clone https://github.com/Pavani2935/TrustVault.git
cd TrustVault/trustvault

python -m venv .venv
```

Activate the virtual environment:

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

**macOS / Linux**
```bash
source .venv/bin/activate
```

Install development dependencies, seed the demo database, and start the server:

```bash
pip install -r requirements-dev.txt
python -m trustvault seed-demo
python -m trustvault serve
```

Open http://127.0.0.1:5000 in a browser.

In development, the application generates local development keys under `instance/`. Do not copy development keys into a production environment.

## 9. Environment configuration

Create a local `.env` file based on `.env.example`. Never commit real secrets. Generate fresh keys using the project's CLI:

```bash
python -m trustvault generate-keys
```

Important settings include:

| Variable | Purpose |
|---|---|
| `TV_ENV` | Runtime environment; use `production` for deployment. |
| `TV_MASTER_KEY` | Protects/wraps file-version encryption keys. |
| `TV_AUDIT_KEY` | HMAC key for audit-chain integrity. |
| `TV_DATABASE_URL` | Optional database connection URL. |
| `TV_COOKIE_SECURE` | Controls secure-cookie behavior where configured. |
| `TV_TRUSTED_PROXIES` | Number of trusted reverse proxies in front of the app. |
| `TV_SESSION_IDLE_MINUTES` | Idle session lifetime. |
| `TV_SESSION_ABSOLUTE_HOURS` | Maximum session lifetime. |
| `TV_MAX_UPLOAD_MB` | Maximum permitted upload size. |
| `TV_TRASH_RETENTION_DAYS` | Trash retention period before purge. |
| `TV_DEMO_MODE` | Protects shared demo accounts and seeded documents. |
| `TV_SEED_DEMO` | Requests demo-data initialization on an empty database. |

Production startup requires valid `TV_MASTER_KEY` and `TV_AUDIT_KEY` values. Keep them separate, private, backed up securely, and outside source control. Losing keys may make encrypted documents or audit verification unavailable. If a key has ever been committed publicly, treat it as exposed and rotate it using a planned migration procedure.

## 10. Docker and deployment

For a production-like local environment using PostgreSQL and the Docker configuration:

```bash
python -m trustvault generate-keys > .env
# Set TV_ENV=production in .env and review all generated configuration.
docker compose up --build
```

The local service is expected at http://localhost:8000.

The repository includes a Render Blueprint in `render.yaml` defining a Docker web service and managed PostgreSQL database. To deploy:

1. Open the Render dashboard and create a new Blueprint from this repository.
2. Ensure the Blueprint points to the `trustvault/` application directory/configuration as expected by the repository.
3. Generate fresh keys with `python -m trustvault generate-keys`.
4. Add `TV_MASTER_KEY` and `TV_AUDIT_KEY` as secret environment variables in Render; do not place their values in the repository.
5. Confirm the database URL, proxy configuration, demo-mode settings, and service health-check path `/healthz`.
6. Deploy and verify the health endpoint, login flow, access controls, and audit verification.

See [DEPLOY.md](DEPLOY.md) for the repository's detailed deployment instructions. Demo mode and seeded demo accounts are intended for demonstrations; review these settings and replace demo credentials before a real production rollout.

## 11. Tests and verification

Run the automated test suite from `trustvault/`:

```bash
python -m pytest
python scripts/mutation_check.py
```

To run against a PostgreSQL test database, set `TV_TEST_DATABASE_URL` to a dedicated test database URL before running pytest. Never point tests at production data.

The tests cover document isolation, revocation, audit integrity, uploads, web security, policy decisions, administrative rules, and access suggestions. The mutation check is intended to confirm that removing security checks causes tests to fail.

## 12. Operational commands

Run these from the application directory:

```bash
python -m trustvault init-db
python -m trustvault create-admin ADMIN_USERNAME
python -m trustvault verify-audit
python -m trustvault purge-expired
python -m trustvault export-schema
```

- `init-db`: initialize database tables and append-only audit protections.
- `create-admin`: create an administrator for a real deployment.
- `verify-audit`: verify the audit chain; a non-zero exit code indicates verification failure.
- `purge-expired`: purge trash past the configured retention period; schedule according to operational policy.
- `export-schema`: regenerate the SQL schema files.

## 13. API and related documents

- [API reference](API.md) — routes, expected callers, and API behavior.
- [Deployment guide](DEPLOY.md) — deployment instructions.
- [Demo script](DEMO_SCRIPT.md) — walkthrough for demonstrating the application.
- [Threat model](../THREATS.md) — threats and mitigations.
- [Prompt/AI log](../PROMPTS.md) — project prompt notes.
- [Project write-up](../WRITEUP.md) — project overview and rationale.
- [Main README](../README.md) — quick start and demo account details.

## 14. Security and privacy checklist

Before using TrustVault with sensitive production documents:

- [ ] Replace demo accounts and credentials; disable demo seeding and demo mode unless intentionally needed.
- [ ] Generate new independent encryption and audit keys; store them in a secret manager or protected environment settings.
- [ ] Configure HTTPS and secure cookies.
- [ ] Use a managed, access-restricted database and encrypted backups.
- [ ] Restrict administrator access and audit administrative activity.
- [ ] Test revocation, denied access, session expiry, and audit verification after deployment.
- [ ] Establish a safe key rotation and recovery procedure.
- [ ] Keep dependencies updated and review vulnerability-audit results.
- [ ] Configure monitoring, backup retention, and incident response.
- [ ] Never treat a successful demo as a substitute for a security review.

## 15. Known boundaries

TrustVault is designed around named, document-specific grants. It does not describe anonymous sharing links or inherited folder permissions. Access suggestions are advisory and must not grant access automatically. Audit logs provide tamper evidence, but deployments should also consider independent backup/anchoring and operational controls for stronger evidence preservation.

## 16. License

Check the repository for a license file and its terms before redistributing or using this project commercially.
