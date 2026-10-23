# TrustVault API (v1)

Base path `/api/v1`. JSON in, JSON out (uploads are `multipart/form-data`; downloads are bytes).
The browser UI uses exactly these endpoints; there are no other data routes.

## Conventions

- **Authentication:** `POST /auth/login` sets a session cookie (`__Host-tv_session` in production,
  `HttpOnly; Secure; SameSite=Strict`). The session lives on the server and is checked on every request.
- **CSRF:** every `POST`/`PUT`/`PATCH`/`DELETE` (except login) must send `X-CSRF-Token: <csrf_token>`
  from the login or `/auth/me` response. Requests with a foreign `Origin` are refused.
- **Errors:** `{"error": {"code", "message", "request_id", "field?"}}`.
  `401` not signed in · `403` signed in but not allowed (or CSRF/Origin) · `404` does not exist
  *or* you have no access to it (indistinguishable on purpose) · `400` validation · `409` conflict ·
  `429` throttled.
- **Unknown JSON fields are rejected** (no mass assignment).
- **"Document permission"** below means the caller's effective permission on *that* document:
  `owner` (it is theirs), `edit` or `read` (an explicit grant), or none. The administrator role
  confers **no** document permission.
- Every row marked 📝 writes an audit event, and every refusal on any row is audited too.

## Who can call what

### Session

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /auth/login` 📝 | Anyone | Body `{username, password}`. JSON only. Throttled per (account, IP) and per IP. Returns `{user, csrf_token, session_expires_at, demo_mode}` |
| `POST /auth/logout` 📝 | Signed in | Deletes the server-side session |
| `GET /auth/me` | Signed in (also with a temporary password) | Current user + CSRF token |
| `POST /auth/change-password` 📝 | Signed in (also with a temporary password) | `{current_password, new_password}`. Ends your other sessions |
| `GET /users/directory` | Role **owner** | Active people an owner can share with: `id, username, display_name, role` |

People with a temporary password (`must_change_password`) get `403 password_change_required`
from everything except the three endpoints marked "also with a temporary password".

### Documents

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /documents` | Signed in | Search: `q` (title or file name), `owner`, `category`, `from`, `to` (YYYY-MM-DD, upload date), `sort` (`created_at`/`title`/`category`, `-` for descending), `limit` ≤100, `offset`. **Only** documents you own or were granted |
| `GET /categories` | Signed in | Categories of documents you can access |
| `POST /documents` 📝 | Role **owner** | Multipart: `title`, `category`, `file`. Content-validated, encrypted. You become the owner |
| `GET /documents/trash` | Role **owner** | Your documents in the trash, with automatic purge date |
| `GET /documents/{id}` 📝 | Document permission **read**, **edit** or **owner** (owner also while in trash) | Metadata + versions. Recorded as a view |
| `GET /documents/{id}/download[?version=n]` 📝 | Document permission **read**, **edit** or **owner** (not while in trash) | `application/octet-stream`, `attachment`, `no-store`, `CSP: sandbox`; `X-Content-SHA256` header. Audit row committed before bytes are sent |
| `PATCH /documents/{id}` 📝 | Document permission **edit** or **owner** | `{title?, category?}` |
| `POST /documents/{id}/versions` 📝 | Document permission **edit** or **owner** | Multipart `file`. New version; older versions remain |
| `DELETE /documents/{id}` 📝 | **owner** of the document | Moves to trash; all grantees lose access immediately |
| `POST /documents/{id}/restore` 📝 | **owner**, document in trash | Grants become active again |
| `DELETE /documents/{id}/purge` 📝 | **owner**, document in trash | Body `{"confirm": "PURGE"}`. Destroys versions, blobs and keys. Refused for seeded documents in demo mode |
| `GET /documents/{id}/activity` | **owner** of the document | Every audit event for this document, including refusals |

### Access

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /documents/{id}/grants` | **owner** of the document | Who has access, since when, granted by whom, from a suggestion or not |
| `PUT /documents/{id}/grants/{userId}` 📝 | **owner** of the document | `{permission: "read"\|"edit", source?: "manual"\|"suggestion"}`. Target must be an active user other than the owner. `source: "suggestion"` is only accepted if the server currently suggests that person |
| `DELETE /documents/{id}/grants/{userId}` 📝 | **owner** of the document | Effective on the grantee's next request |
| `GET /documents/{id}/suggestions` 📝 | **owner** of the document | Up to 5 people, with reasons. Never grants anything. Recorded as `suggestion.shown` |
| `POST /documents/{id}/suggestions/{userId}/dismiss` 📝 | **owner** of the document | Recorded as `suggestion.dismissed` |

### Administration (role **admin** only, every refusal recorded as `authz.role_denied`)

| Method & path | Notes |
|---|---|
| `GET /admin/overview` | Totals, last-24h counts, alerts, recent permission changes |
| `GET /admin/users` | Everyone, with role, status, owned documents, active sessions |
| `POST /admin/users` 📝 | `{username, display_name?, role, password}`. The person must change the password at first sign-in |
| `PATCH /admin/users/{id}` 📝 | `{display_name?, role?, is_active?}`. Role change and deactivation end all their sessions. Cannot change your own role or deactivate yourself. An owner who still owns documents cannot be demoted |
| `POST /admin/users/{id}/reset-password` 📝 | `{password}` (temporary). Ends all their sessions |
| `POST /admin/users/{id}/revoke-sessions` 📝 | Sign the person out everywhere |
| `GET /admin/documents` | Metadata only: title, category, owner, grant count, state. No file names, versions or content |
| `POST /admin/documents/{id}/transfer` 📝 | `{new_owner_id, reason}`. New owner must be an active **owner**-role account. Previous owner loses access |
| `GET /admin/audit` | Filters: `action` (prefix), `outcome`, `actor`, `document_id`, `target_user_id`, `from`, `to`, `limit` ≤500, `before_seq` (pagination) |
| `POST /admin/audit/verify` 📝 | Recomputes the whole HMAC chain, checks sequence gaps and checkpoints, records a new checkpoint |

### Other

| Method & path | Who | Notes |
|---|---|---|
| `GET /` and `/assets/*` | Anyone | The single-page UI (static files, no data) |
| `GET /healthz` | Anyone | `{"status": "ok"}` |

## Audit event actions

`auth.login`, `auth.logout`, `auth.change_password`, `authz.role_denied`,
`document.create`, `document.view`, `document.download`, `document.edit_metadata`,
`document.upload_version`, `document.delete`, `document.restore`, `document.purge`,
`document.transfer_ownership`, `document.<action>` with outcome `denied` for any refused document action,
`grant.set`, `grant.revoke`, `suggestion.shown`, `suggestion.dismissed`,
`user.create`, `user.update`, `user.role_change`, `user.activate`, `user.deactivate`,
`user.reset_password`, `user.revoke_sessions`, `audit.verify`.

Each event: `seq` (gap-free), `event_id`, `occurred_at` (UTC), actor id/username/role, `action`,
`outcome` (`success`/`denied`/`error`), `document_id`, `target_user_id`, `ip`, `request_id`,
`details` (JSON), `prev_hash`, `entry_hash`.

## Example

```bash
B=https://<host>/api/v1
curl -s -c jar -H 'Content-Type: application/json' -d '{"username":"victor","password":"Viewer#Vault2026"}' $B/auth/login
CSRF=$(curl -s -b jar $B/auth/me | python -c 'import sys,json;print(json.load(sys.stdin)["csrf_token"])')
curl -s -b jar "$B/documents?q=offer"
curl -s -b jar -OJ "$B/documents/<id>/download"
curl -s -b jar -X DELETE -H "X-CSRF-Token: $CSRF" "$B/documents/<id>"   # 403: victor only has read
```
