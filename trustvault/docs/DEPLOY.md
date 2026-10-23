# Deploying TrustVault from a clean clone

The app is one Docker image plus one PostgreSQL database. Any host that runs a Dockerfile and
offers PostgreSQL works; the steps below use Render because `render.yaml` describes the whole
deployment.

## 0. Before you start

```bash
git clone <your-repo-url> trustvault && cd trustvault
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest                       # should be all green
python -m trustvault generate-keys     # copy the two lines somewhere safe (password manager)
```

`TV_MASTER_KEY` decrypts every file. **If it is lost, the files are gone. If it leaks, together
with a database copy, the files are readable.** Store it in the host's secret settings and in a
password manager, never in the repository. `TV_AUDIT_KEY` must be a different value.

## 1. Render (Blueprint)

1. Push the repository to GitHub.
2. In Render: **New → Blueprint**, choose the repository. Render reads `render.yaml` and proposes
   a PostgreSQL database `trustvault-db` and a Docker web service `trustvault`.
3. When asked for `TV_MASTER_KEY` and `TV_AUDIT_KEY`, paste the values from step 0.
4. Apply. The first build takes a few minutes. On start the container runs
   `python -m trustvault init-db` (tables and append-only triggers), then `seed-demo`
   (only on an empty database), then gunicorn.
5. Open `https://<service>.onrender.com/healthz` → `{"status":"ok"}`, then the root URL, and sign in
   with the demo accounts in the README.
6. Put the URL at the top of `README.md`.

Settings that `render.yaml` already sets: `TV_ENV=production` (refuses to start without keys or
with SQLite), `TV_TRUSTED_PROXIES=1` (Render's proxy is the one hop we trust for client IPs),
`TV_DEMO_MODE=true` and `TV_SEED_DEMO=true` for the shared demo.

Free-tier notes: a free web service sleeps when idle, so the first request after a pause is slow.
Free PostgreSQL instances on Render are time-limited; check the current terms and upgrade or
re-create before the interview if needed (re-creating gives a fresh, re-seeded database).

## 2. Any other Docker host (Railway, Fly.io, a VM)

Provide these environment variables and run the image:

| Variable | Value |
|---|---|
| `TV_ENV` | `production` |
| `TV_DATABASE_URL` | `postgresql://user:pass@host:5432/db` (`postgres://` also accepted) |
| `TV_MASTER_KEY`, `TV_AUDIT_KEY` | from `python -m trustvault generate-keys` |
| `TV_TRUSTED_PROXIES` | number of reverse proxies in front of the app (usually `1`) |
| `FORWARDED_ALLOW_IPS` | `*` behind a platform proxy (gunicorn setting) |
| `TV_SEED_DEMO`, `TV_DEMO_MODE` | `true` for a public demo, otherwise leave unset |
| `PORT` | set by most platforms; defaults to 8000 |

For a real (non-demo) deployment, leave `TV_SEED_DEMO` unset and create the first administrator:

```bash
TV_BOOTSTRAP_PASSWORD='<strong password>' python -m trustvault create-admin alice --display-name "Alice"
```

## 3. Local, production-like

```bash
python -m trustvault generate-keys > .env && echo "TV_ENV=production" >> .env
docker compose up --build           # http://localhost:8000, PostgreSQL in a container
```

## 4. Operating it

| Task | Command / place |
|---|---|
| Verify the audit chain | Admin → Activity & alerts → "Verify audit chain now", or `python -m trustvault verify-audit` (exit 1 on tampering) |
| Purge the trash after retention | `python -m trustvault purge-expired` daily (Render Cron Job or any scheduler) |
| Ship audit evidence off-box | Every event and checkpoint is written to stdout as JSON (`trustvault.audit`, `trustvault.audit.anchor`); point the platform's log drain at a store the DB admins do not control. Optionally set `TV_AUDIT_ANCHOR_FILE` to an append-only volume |
| Least-privilege DB role (PostgreSQL) | Run migrations as the table owner; run the app as a role with `INSERT, SELECT` only on `audit_events` and `audit_checkpoints` (see `db/roles.postgres.sql`) |
| Back up | Database backups contain only ciphertext and wrapped keys; keep `TV_MASTER_KEY` backed up separately |

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Container exits with `TV_MASTER_KEY and TV_AUDIT_KEY are required in production` | Set both secrets (step 0). This is deliberate: there is no default key |
| `Use PostgreSQL in production` | `TV_DATABASE_URL` is missing or points at SQLite |
| Sign-in works but every change fails with `bad_origin` | The app thinks it is served over `http` behind an `https` proxy. Set `TV_TRUSTED_PROXIES` to the number of proxies (1 on Render) |
| Sign-in "works" but you are immediately signed out on plain `http://` | Production cookies are `Secure`; use https, or `TV_COOKIE_SECURE=false` for local http only |
| Downloads fail with `integrity_error` | The stored ciphertext or its hash does not match. Check the admin alerts and `verify-audit`; restore from backup. Also happens if `TV_MASTER_KEY` changed |
