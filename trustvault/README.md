# TrustVault

Secure document sharing where the wrong person cannot reach a document, and where you can
prove who did.

- **Live demo:** `https://<your-service>.onrender.com` ← replace after deploying (see [docs/DEPLOY.md](docs/DEPLOY.md))
- **Threat model:** [THREATS.md](THREATS.md) · **AI log:** [PROMPTS.md](PROMPTS.md) · **Write-up:** [WRITEUP.md](WRITEUP.md)
- **API (with who may call each endpoint):** [docs/API.md](docs/API.md) · **Demo script:** [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)

## Demo accounts

| Role | Username | Password | What to try |
|---|---|---|---|
| Administrator | `admin` | `Admin#Vault2026` | Activity & alerts, audit trail, verify the chain, deactivate a person. Cannot open any document. |
| Document owner | `olivia` | `Owner#Vault2026` | Owns 4 documents. Grant, change, revoke access. See who reached each document. |
| Document owner | `oscar` | `Owner2#Vault2026` | Owns 3 documents; try the access suggestions on "Q3 audit sampling plan". |
| Viewer | `victor` | `Viewer#Vault2026` | Has **read** on one document only ("Offer letter"). |
| Viewer | `vera` | `Viewer2#Vault2026` | External auditor: **read** on two documents, **edit** on one. |

The demo runs with `TV_DEMO_MODE=true`: these shared accounts cannot be deactivated or have
their passwords changed, and seeded documents cannot be purged, so one visitor cannot break
the demo for the next. Create your own accounts and documents to try those actions.

## What it does

- **Three roles.** Administrators manage people and read the audit trail. Owners upload and
  share. Viewers only see what was shared with them. Roles decide what you can *do*; only
  ownership and grants decide which *documents* you can reach.
- **Per-document grants** to named people: `read` (view, download) or `edit` (also rename and
  upload new versions). Only the owner can share, change or revoke. No groups, no folder
  inheritance, no anonymous links.
- **Immediate revocation.** Every request re-checks the grant table and the session. Revoking a
  grant, deactivating a person, changing their role or resetting their password takes effect on
  their very next request. Nothing was issued that could outlive that: no signed links, no
  bearer tokens, no cached decisions, and downloads are `Cache-Control: no-store`.
- **Audit trail with evidence value.** Views, downloads, uploads, edits, deletions, grants,
  revocations, logins and *every refused attempt*, written in the same transaction as the action.
  Append-only at the database level, hash-chained with an HMAC key that is not in the database,
  checkpointed, and mirrored to the log stream. Admins can verify the whole chain in one click.
- **Encrypted storage.** Each file version is encrypted with its own AES-256-GCM key, wrapped by
  a master key held only in the environment. Ciphertext is bound to its document, so swapping
  blobs in the database is detected rather than served. Purging deletes the keys.
- **Upload validation by content**, not by name or browser-supplied type: PDF, Office (non-macro),
  images, text/CSV only; scripts in PDFs, macros, HTML/SVG, archives and zip bombs are refused.
- **Search** by name, owner, category and date range, always scoped to what you can open.
- **Versions, trash, restore, purge**, with 30-day retention for the trash.
- **Admin activity view** with alerts: probing (repeated refusals), bulk downloads, brute force,
  new administrators, ownership transfers, integrity failures, and downloads by people who were
  then deactivated.
- **Access suggestions** for owners: explainable, rule-based, never grant on their own; the
  suggestion, the acceptance or the dismissal are all audited.

## Architecture

```
Browser (vanilla JS, CSP script-src 'self', textContent only)
   │  same-origin JSON  ·  session cookie (HttpOnly, SameSite=Strict, __Host-)  ·  X-CSRF-Token
   ▼
Flask API  /api/v1/*            ← the only interface; the UI has no private routes
   │  before_request: resolve server-side session → check Origin + CSRF
   ▼
services/*  ── every document operation starts with ──►  load_document(actor, id, action)
   │                                                      └─► security/policy.decide()  ◄── THE decision
   ├─ audit.record()  (same DB transaction, HMAC chain, gap-free seq)
   ├─ security/crypto (AES-256-GCM per version, key wrapped by TV_MASTER_KEY)
   ▼
PostgreSQL (SQLite for local dev)  ·  audit tables protected by append-only triggers
```

**Where is the authorisation decision made when someone downloads a file?**
`trustvault/security/policy.py::decide()`, called from
`trustvault/services/documents.py::load_document()`, which `download()` calls before it touches the
version, the blob or the key. If that call were removed, `tests/test_isolation.py::test_access_matrix`
fails for every person who has no grant, and `scripts/mutation_check.py` proves it.

## Run it locally (2 minutes)

Python 3.11+:

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m trustvault seed-demo        # creates instance/trustvault.db and demo data
python -m trustvault serve            # http://127.0.0.1:5000
```

In development, keys are generated into `instance/dev-keys.json`. In production the app refuses
to start without `TV_MASTER_KEY` and `TV_AUDIT_KEY`.

Production-like (PostgreSQL + gunicorn) with Docker:

```bash
python -m trustvault generate-keys > .env && echo "TV_ENV=production" >> .env
docker compose up --build             # http://localhost:8000
```

Deploying to Render (free tier) from a clean clone: [docs/DEPLOY.md](docs/DEPLOY.md).

## Tests

```bash
python -m pytest                                  # ~870 tests, SQLite
TV_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/tvtest python -m pytest   # same suite on PostgreSQL
python scripts/mutation_check.py                  # removes each security check; every one must break a test
```

| File | Proves |
|---|---|
| `tests/test_isolation.py` | Every person × every seeded document × every document endpoint matches the grant table; search, categories, IDs, versions, mass assignment, role gates |
| `tests/test_revocation.py` | Revoke, downgrade, deactivate, role change, password reset, logout, expiry, trash, ownership transfer all take effect on the next request |
| `tests/test_audit.py` | Who/what/when for every action and refusal; DB refuses UPDATE/DELETE/TRUNCATE; edits, deletions, keyless rewrites and truncation are detected; concurrency keeps the chain gap-free |
| `tests/test_uploads.py` | Content-based validation, sanitised names, encryption at rest, blob-swap detection |
| `tests/test_web_security.py` | CSRF, Origin, cookie flags, security headers, enumeration, brute-force throttling |
| `tests/test_policy.py` | `decide()` against an independently written reference for all 720 combinations |
| `tests/test_admin_and_suggestions.py` | Admin rules, demo protection, alerts, suggestions never widen access |

CI (`.github/workflows/ci.yml`) runs the suite on SQLite and PostgreSQL, the mutation check and a dependency audit.

## Operating it

```bash
python -m trustvault init-db           # tables + append-only triggers
python -m trustvault create-admin NAME # first administrator for a real deployment
python -m trustvault verify-audit      # exit code 1 if the audit chain was tampered with
python -m trustvault purge-expired     # run daily: purge trash older than TV_TRASH_RETENTION_DAYS
python -m trustvault export-schema     # regenerate db/schema.*.sql
```

Database schema: [db/schema.postgres.sql](db/schema.postgres.sql) and [db/schema.sqlite.sql](db/schema.sqlite.sql)
(the app creates it automatically with `init-db`). Configuration: [.env.example](.env.example).
