# TrustVault: write-up

## What I built

A document vault with three roles (administrator, owner, viewer), per-document `read`/`edit`
grants to named people, immediate revocation, versions, trash/restore/purge, search, content-based
upload validation, encryption at rest, a tamper-evident audit trail that records refusals, an
admin activity view with alerts, and an access-suggestion feature that can only ever propose.

Stack: Python 3.12, Flask (JSON API), SQLAlchemy, PostgreSQL in production (SQLite for local
development and fast tests), Argon2id, AES-256-GCM via `cryptography`, a dependency-free vanilla
JavaScript UI, gunicorn in a non-root Docker image, deployed on Render.

**Why this stack.** The marks are for security, so I wanted the smallest surface I could reason
about completely: one process, one JSON API that the UI also uses, no build step, no framework
magic between the request and the authorisation decision. Flask makes every route visible as a
plain function. PostgreSQL gives me transaction-scoped advisory locks and statement-level triggers
for the audit trail. The same test suite runs against SQLite and PostgreSQL.

## The permission model, in my words

- **Ownership and grants decide which documents you can reach. Roles decide what kind of thing you
  can do.** These are kept separate on purpose.
- Every document has exactly one owner. The owner can do everything to it, including sharing.
- Anyone else needs a grant: one row saying *this person* may *read* (view and download) or *edit*
  (also rename and upload new versions) *this document*. No groups, no folders, no inheritance, no
  links. If there is no row, there is no access, and the API answers 404 exactly as if the document
  did not exist.
- Only the owner can share, change or revoke. An editor cannot re-share, so access can only widen
  through the owner's own decision.
- The **administrator** role gives no access to documents. Admins manage people (create,
  deactivate, change roles, reset passwords, end sessions), transfer ownership when someone leaves
  (with a written reason, audited and alerted), and read the audit trail. They see document
  metadata, not content.
- Deleting puts a document in the owner's trash: invisible to grantees, restorable, purged
  after 30 days. Purging destroys the per-version encryption keys.

The rule is implemented once, in `security/policy.py::decide()`, and is checked against an
independently written reference for all 720 combinations in `tests/test_policy.py`.

**Where is the authorisation decision made when someone downloads a file, and what if that line
were removed?** `services/documents.py::download()` first calls `load_document(actor, id,
Action.DOWNLOAD)`, which loads the caller's grant and calls `decide()`. Only if that allows it does
the code read the version row, unwrap the key and decrypt. If the `if not decision.allowed:` check
were removed, everyone could download everything: `test_access_matrix` fails for all 23 person/
document pairs without a grant, and `scripts/mutation_check.py` demonstrates it automatically.

## What "taking access away immediately" means here, and its cost

Nothing that grants access is ever handed to the client. The cookie is a random token that only
identifies a server-side session row; the grant table is read on every request. So revoking a
grant, deactivating a person, changing their role or resetting their password takes effect on
their next request, and a copied cookie is useless after logout. Downloads are `no-store` so the
browser cannot re-open them from cache.

The cost: two indexed lookups per request and no edge caching of anything private, which is fine
at this scale. What it cannot do: recall a file that was already downloaded. For that the
audit trail records exactly who downloaded which version (with its SHA-256) and when.

## How the audit trail is protected

Written in the same transaction as the action (no action without its record; refusals committed
even though the request fails) → `seq` assigned without gaps under a lock → each entry's hash is
an HMAC over the previous hash and the entry, keyed with a secret that is not in the database →
database triggers reject UPDATE, DELETE and TRUNCATE → checkpoints of the chain head in a
separate append-only table → every event and checkpoint also written to the log stream, outside
the database. The admin page and `python -m trustvault verify-audit` recompute everything and name
the first broken row. Tests edit, delete, truncate and re-hash rows directly in the database and
check each is detected.

The honest limit: someone holding database superuser rights, the audit key *and* control of the
log store could rewrite history. In production the log stream should go to a separately
administered WORM store.

## How I used AI, and where it was wrong

I used AI to generate a starter, then to review and rebuild it, and for most of the code and tests.
The starter was confidently wrong in the places that matter most: a default session secret that
let anyone forge an admin session, signed-cookie sessions that cannot be revoked, no way to
deactivate a leaver, admins able to read every document, a category list that leaked across
users, no CSRF protection, and an audit chain anyone with database access could recompute. During
the rebuild the AI also proposed audit gap detection that would have fired on every rollback, a
LIKE-based login throttle an attacker could steer, a trigger test that could not fail, and a
global header hook that silently removed the download sandbox. Details and fixes are in
[PROMPTS.md](PROMPTS.md). The habit that caught them: for every check, delete it and see which test
fails; `scripts/mutation_check.py` does that for 39 checks.

## What I deliberately did not build

Anonymous share links (a forwarded link cannot be tied to a person), groups and folder
inheritance (the brief's "one folder, forty files" problem; groups would come next), MFA/SSO,
malware scanning, full-text search inside documents, key-rotation tooling, WORM log export and
two-person approval for ownership transfers. Reasons are in [THREATS.md](THREATS.md).

## What is unfinished or weak

- PDF active-content detection is a marker scan; compressed object streams can hide markers.
- No MFA: a correctly guessed password from many IPs is only throttled per IP and alerted.
- No per-user quotas or global rate limiting; the right place is the reverse proxy.
- Admins can still, in several audited steps, give themselves a route to a document by creating an
  account and transferring ownership to it. Detected and alerted, not prevented.
- Alerts are computed when the admin opens the page, not pushed.
- The shared demo needs `TV_DEMO_MODE` so one visitor cannot lock out the next; that flag is
  demo-only.
