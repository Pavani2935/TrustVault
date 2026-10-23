# THREATS.md: how TrustVault could be broken

The three promises, and how each is kept:

1. **A document is reachable only by someone who was granted it.** One function decides
   (`security/policy.py::decide`), one function loads documents for callers
   (`services/documents.py::load_document`), and every document route goes through it. The
   browser UI calls the same JSON API an attacker would; there are no other routes to the data.
2. **You can prove who reached it.** Every view, download, change and *refusal* is written
   in the same database transaction as the action, into a gap-free, HMAC-chained, append-only
   ledger, mirrored to the log stream and checkpointed.
3. **Taking access away works immediately.** Nothing is ever issued that outlives a server-side
   check: sessions are server-side rows, grants are re-read on every request, there are no
   signed or shareable links, and responses are `no-store`.

**Who might attack it:** an outsider with no account; a logged-in viewer probing for other
documents; a grantee trying to widen their access; a former employee holding an old cookie;
a malicious or careless owner; an administrator acting outside their role; someone with direct
database access; someone who stole a backup.

**Status key:** **Closed** = prevented by design and covered by a test. **Mitigated** = reduced,
with residual risk stated. **Accepted** = knowingly left, with the reason.

Test names refer to files in `tests/`. `scripts/mutation_check.py` removes 39 of these checks one
at a time and confirms the suite fails each time (results at the end of this file).

---

## A. Reaching a document you were not given

| # | Threat / route | What stops it | Test | Status |
|---|---|---|---|---|
| A1 | **IDOR**: change the ID in `/documents/{id}`, `/download`, `/versions`, `/grants`, `/activity`, `/suggestions`, `/restore`, `/purge` | Every route calls `load_document(actor, id, action)`, which authorises against the owner and the caller's own grant row before returning anything | `test_isolation::test_access_matrix` (7 documents × 5 people × 14 operations) | Closed |
| A2 | Hide the button but call the endpoint directly | UI is not trusted; same API, same checks | same matrix (it never uses the UI) | Closed |
| A3 | Download an **older version** of a document you lost access to | Version is selected *after* authorisation of the document | `test_revocation::test_revoked_grant_stops_working_on_the_next_request` | Closed |
| A4 | `HEAD` instead of `GET` on the download URL | Flask runs the same handler; authorised and audited (`method` recorded) | matrix "download HEAD" | Closed |
| A5 | **Search / listing** leaks titles of documents you cannot open | Listing uses `accessible_filter()`, the SQL mirror of the policy; result counts are scoped too | `test_search_never_returns_documents_you_cannot_open` | Closed |
| A6 | **Category list** leaks that "Board" or "Layoffs 2026" exists | Categories derived only from accessible documents | `test_categories_only_show_accessible_documents` | Closed |
| A7 | LIKE wildcards (`%`, `_`) in search to match everything | Wildcards escaped; search is still inside the access scope | `test_search_like_wildcards_are_literal` | Closed |
| A8 | **Existence oracle**: 403 vs 404 tells you a document exists | No relationship ⇒ 404 identical to a random UUID; 403 only when you already have some access | `test_nonexistent_and_forbidden_look_identical` | Closed |
| A9 | Malformed IDs: SQL, `../`, NUL, 300-char strings, uppercase UUIDs | Strict UUID parsing and canonicalisation before lookup; parameterised SQL; refused attempts logged | `test_malformed_document_ids_are_refused_and_logged`, `test_uppercase_uuid_is_authorised_the_same_way` | Closed |
| A10 | `?version=` injection (`1 OR 1=1`, `../1`, `-1`) | Digits only, matched against the authorised document's own versions | `test_version_parameter_cannot_escape_the_document` | Closed |
| A11 | **Privilege widening by an edit grantee**: re-share, grant themselves edit, delete, see the grant list | `MANAGE_GRANTS`, `DELETE`, `VIEW_ACTIVITY` are owner-only in the policy | `test_edit_grantee_cannot_reshare_delete_or_see_grants` | Closed |
| A12 | **Mass assignment**: `PATCH {"owner_id": me}` or extra fields when creating users | Strict field allow-lists; unknown fields are a 400 | `test_mass_assignment_of_owner_is_rejected`, `test_unknown_json_fields_are_rejected` | Closed |
| A13 | **Administrator reads everything** ("admin is a superuser") | The policy gives the admin role *no* document rights. Admins see metadata (title, owner, category, grant count), never content or file names | `test_administrator_cannot_read_any_document_content`, `test_policy::test_decide_matches_reference` (role makes no difference) | Closed |
| A14 | Grant to a deactivated or non-existent user, or `permission: "owner"` | Target must exist and be active; permission must be `read`/`edit` | `test_owner_cannot_grant_to_themselves_or_unknown_or_inactive` | Closed |
| A15 | Grantee reaches a document **in the trash** | Trash is owner-only; grants go dormant | `test_trashed_document_is_invisible_to_grantees` | Closed |
| A16 | Viewer or admin **uploads** to plant content | Only the owner role can create documents (refusal audited) | `test_only_owners_upload_new_documents` | Closed |
| A17 | Non-admin calls `/admin/*`, viewer calls the user directory | Role gate (and audited as `authz.role_denied`) | `test_role_gated_endpoints` | Closed |
| A18 | No session at all | 401 everywhere except login and static assets | `test_unauthenticated_requests_get_nothing` | Closed |
| A19 | A grant row for *another* user or *another* document is used by mistake (query bug) | `decide()` re-checks that the grant's user and document match the caller and the document | `test_policy::test_grant_for_another_user_or_document_is_ignored` + mutant | Closed |
| A20 | A future developer adds a route and forgets the check | Only `load_document` returns documents to services; reviewers look for it. The matrix test covers all current routes | — | **Accepted** (process control, not code). A route that queries `Document` directly would bypass it; I would add a lint rule in a longer project |

## B. Revocation and things issued earlier

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| B1 | Grantee keeps using the same browser session after revocation | Grant table re-read on every request; no caching | `test_revoked_grant_stops_working_on_the_next_request` | Closed |
| B2 | Edit downgraded to read, but edits keep working | Same | `test_downgrading_edit_to_read_takes_effect_immediately` | Closed |
| B3 | **Leaver**: deactivated person's cookie still works | Deactivation deletes all their sessions; every request also checks `is_active` | `test_deactivation_kills_existing_sessions_and_blocks_login`, `test_deactivated_user_with_stolen_cookie_is_refused_even_if_session_row_survives` | Closed |
| B4 | Signed-cookie replay after logout (the Flask default session) | Opaque random token, server-side row deleted on logout | `test_logout_invalidates_the_token_server_side` | Closed |
| B5 | Role change or password reset does not end sessions | Both end all sessions | `test_role_change_ends_sessions`, `test_password_reset_ends_sessions` | Closed |
| B6 | Stolen session elsewhere survives a password change | Changing your password ends your other sessions | `test_changing_own_password_signs_out_other_sessions` | Closed |
| B7 | Forgotten session lives forever | 30-min idle, 8-h absolute expiry, enforced server-side | `test_idle_and_absolute_session_expiry` | Closed |
| B8 | Revoked person re-opens the file **from browser or proxy cache** | `Cache-Control: no-store` on every API response, including downloads | `test_downloads_are_never_cacheable` | Closed |
| B9 | Previous owner keeps access after an ownership transfer | Ownership is a single column; the old owner has no grant afterwards | `test_ownership_transfer_removes_previous_owner` | Closed |
| B10 | Download already in flight when access is revoked | The decision is made before the first byte; a response already being sent (max 10 MB) completes | — | **Accepted.** Cost of preventing: streaming with re-checks, for a window of seconds |
| B11 | Bytes already downloaded before revocation | Cannot be recalled by any system. The audit trail records exactly who downloaded which version (SHA-256) and when | `test_download_is_recorded_with_who_what_when` | **Accepted** (inherent); evidence is what we can offer |
| B12 | Restoring a trashed document silently re-activates old grants | Intended (restore means "undo delete"), shown in the UI and recorded as `document.restore` with the dormant grant count recorded at delete time | `test_trash_removes_access_and_restore_brings_back_existing_grants` | Accepted by design |

**What "immediately" costs:** one indexed session lookup and one grant lookup per request, and
no CDN caching of anything behind login. At this scale that is cheap; at very large scale I would
add a short-TTL cache *with* explicit invalidation on revoke, never a long-lived signed URL.

## C. Authentication and sessions

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| C1 | Password guessing / credential stuffing on one account | Throttle 5 failures per (account, IP) per 15 min, 30 per IP; correct password also refused while throttled | `test_brute_force_is_throttled_per_account_and_ip` | Mitigated |
| C2 | Attacker locks a real person out by failing their logins | No account lockout: throttling is per (account, IP), so other IPs still work | same (oscar still logs in) | Closed |
| C3 | Distributed guessing from many IPs | Alert "failed sign-ins for account X" in the admin view; strong password policy | `test_password_policy_is_enforced` | **Accepted** residual: no MFA in this version (see "not built") |
| C4 | Username enumeration by message or timing | Identical message; Argon2 verify against a dummy hash for unknown users | `test_login_errors_do_not_reveal_whether_an_account_exists`, `test_deactivated_account_gets_the_same_login_error` | Closed |
| C5 | Weak or reused passwords | ≥12 chars, 3 character classes, not containing the username, not common; Argon2id hashing | `test_password_policy_is_enforced` | Mitigated |
| C6 | Admin-set temporary password reused | `must_change_password`: only change-password, me and logout work until changed | `test_password_reset_ends_sessions`, `test_admin_creates_user_who_must_change_password` | Closed |
| C7 | Session token stolen from the database | Only SHA-256 of the token stored | `test_session_token_is_stored_hashed` | Closed |
| C8 | Session fixation | New random token at every login; previous session of that browser ended | — | Closed |
| C9 | Cookie theft via JavaScript or plain HTTP, subdomain cookie injection | `HttpOnly`, `SameSite=Strict`, `Secure` + `__Host-` prefix in production, HSTS | `test_session_cookie_flags`, `test_secure_cookie_uses_host_prefix` | Closed |
| C10 | Forged session via a default secret (the starter fell back to `"dev-only-change-me"`) | No signing secret exists to guess; production refuses to start without real keys | config check in `config.load_settings` | Closed |
| C11 | IP spoofing via `X-Forwarded-For` to dodge throttling | `ProxyFix` only trusts the configured number of proxies (`TV_TRUSTED_PROXIES`) | — | Mitigated (must be configured correctly per host) |

## D. Browser-level attacks

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| D1 | **CSRF**: malicious page makes an owner grant access to the attacker | Per-session CSRF token in a header on every state change, `SameSite=Strict`, Origin check | `test_state_change_without_csrf_token_is_refused`, `test_csrf_token_of_another_session_is_useless`, `test_cross_origin_requests_are_refused` | Closed |
| D2 | Login CSRF (log the victim into the attacker's account) | Login accepts JSON only (a cross-site form cannot send it without CORS) + Origin check | `test_login_requires_json_so_html_forms_cannot_post_it` | Closed |
| D3 | **Stored XSS** via title, category, file name or audit details | UI writes all data with `textContent`; strict CSP (`script-src 'self'`, no inline) | `test_text_fields_are_validated` (payload stored as text), `test_security_headers_everywhere` | Closed |
| D4 | Uploaded HTML/SVG executes in our origin when downloaded | HTML/SVG refused; downloads are `attachment`, `application/octet-stream`, `nosniff`, `CSP: sandbox` | `test_dangerous_or_mismatched_files_are_refused`, `test_downloads_are_sandboxed_attachments` | Closed |
| D5 | Clickjacking the grant form | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | `test_security_headers_everywhere` | Closed |
| D6 | Document IDs leaking via Referer to third parties | `Referrer-Policy: no-referrer`; no third-party resources at all | `test_security_headers_everywhere` | Closed |
| D7 | CORS misconfiguration | No CORS headers are ever sent; cross-origin reads are blocked by the browser | — | Closed |

## E. The audit trail as evidence

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| E1 | Action happens but is not recorded (crash between the two) | Audit row is written in the **same transaction** as the change; downloads commit the audit row before any byte is sent | `test_uploads_edits_grants_deletions_are_all_recorded`, `test_download_is_recorded_with_who_what_when` | Closed |
| E2 | **Refused attempts are not recorded** | `load_document` records and commits every refusal (with reason) before raising; role-gate refusals, failed logins, throttling, upload rejections too | `test_every_refusal_is_recorded_with_a_reason`, `test_role_denials_and_failed_logins_are_recorded`, matrix counts refusals per person | Closed |
| E3 | Someone runs `UPDATE`/`DELETE`/`TRUNCATE` on the audit table | Database triggers reject them (both SQLite and PostgreSQL) | `test_database_refuses_to_alter_audit_rows`, `test_database_refuses_truncate_on_postgres` | Closed |
| E4 | DB superuser disables triggers and **edits** a row | HMAC chain breaks; verification names the row | `test_edited_event_is_detected` | Closed (detected) |
| E5 | … **deletes** a row in the middle | `seq` is assigned head+1 under a lock, so gaps are tampering, not rollbacks | `test_deleted_event_is_detected` | Closed (detected) |
| E6 | … edits a row and **recomputes the chain** (defeats a plain SHA-256 chain, which the starter used) | Chain is keyed with `TV_AUDIT_KEY`, held only in the app's environment | `test_rewriting_the_chain_without_the_secret_key_is_detected` | Closed (detected) |
| E7 | … deletes the **newest** events (tail truncation, invisible to a chain) | Checkpoints every 50 events in a separate append-only table, plus every event and checkpoint shipped to the log stream / anchor file outside the DB | `test_truncating_the_newest_events_is_detected_by_checkpoints`, `test_external_anchor_file_catches_truncation_after_the_last_db_checkpoint` | Mitigated: events after the last checkpoint are only provable from the external log copy |
| E8 | Attacker with **DB superuser + `TV_AUDIT_KEY` + control of the log store** rewrites everything | Nothing in-app can stop someone who owns every copy | — | **Accepted.** Production answer: ship logs to a separately-administered WORM store (S3 Object Lock / a SIEM) whose admins are not the DB admins |
| E9 | Two concurrent requests read the same chain head and fork the chain | PostgreSQL advisory lock / SQLite `BEGIN IMMEDIATE` around head-read + insert | `test_concurrent_requests_keep_the_chain_gap_free` | Closed |
| E10 | Log injection: username with newlines forges log lines | Non-printable characters stripped, lengths capped; log lines are JSON | `test_attacker_controlled_strings_cannot_forge_log_lines` | Closed |
| E11 | Audit refers to a purged document or user and loses meaning | Audit has no foreign keys and copies titles/usernames/hashes into `details` | purge test | Closed |
| E12 | Non-admins read the global audit trail | Admin only; owners see only their own documents' activity | `test_audit_trail_is_admin_only`, `test_owner_sees_document_activity_but_grantee_does_not` | Closed |
| E13 | Audit floods the database (DoS by failed logins) | Throttling bounds failed logins per IP; no retention purge of audit by design | — | **Accepted**: evidence is never auto-deleted; disk monitoring is an ops task |
| E14 | Clock manipulation to reorder events | Order is the chain `seq`, not the timestamp; timestamps are server UTC | — | Mitigated |

## F. Storage and cryptography

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| F1 | Guess a file path / static URL | Files are not on a filesystem path or URL at all; ciphertext lives in a DB table reachable only through `download()` | — | Closed |
| F2 | Stolen database dump or backup | AES-256-GCM per version; data keys wrapped by `TV_MASTER_KEY` which is not in the DB | `test_files_are_encrypted_at_rest` | Closed |
| F3 | DB-level attacker **swaps ciphertext** to make a readable document serve another's bytes | GCM associated data binds ciphertext to document+version; failure is a 500 and an `integrity_failure` alert, never wrong bytes | `test_swapped_ciphertext_is_detected_not_served` | Closed |
| F4 | Silent corruption, or the stored SHA-256 edited so downloads carry a false fingerprint | GCM tag + stored SHA-256 re-checked on every download; mismatch is refused and audited as `error` | `test_download_returns_exact_bytes_and_hash`, `test_tampered_hash_metadata_is_detected_not_served` (added after the mutation check found this untested) | Closed |
| F5 | Purged document recoverable from leftovers | Purge deletes the wrapped data keys (crypto-shredding) and blobs | `test_purge_destroys_document_and_keys` | Mitigated (DB backups keep ciphertext, but no key for it remains) |
| F6 | Master key compromise | Key only in the host's secret store; `key_id` stored per version so a rotation can re-wrap keys | — | **Accepted**: rotation tooling not built (re-wrapping is cheap because only data keys are re-encrypted) |
| F7 | Master key and audit key are the same | Startup refuses identical keys | `config.load_settings` | Closed |

## G. Upload validation

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| G1 | Executable renamed `.pdf` | Type detected from content; extension must match | `test_dangerous_or_mismatched_files_are_refused` | Closed |
| G2 | PDF with JavaScript / launch / embedded files | Marker scan refuses `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA` | same | Mitigated: compressed object streams can hide markers. A real deployment adds a sandboxed scanner (ClamAV / CDR) |
| G3 | Macro-enabled Office file named `.docx` | `vbaProject.bin` refused, `.docm` etc. not allowed | same | Closed |
| G4 | Zip bomb / path-traversal entries in Office container | Entry count, compression-ratio and path checks; nothing is ever extracted | `test_zip_bomb_ratio_is_refused`, `test_plain_zip_is_refused` | Closed |
| G5 | Path traversal or RTL-override in the file name | Path components stripped, bidi controls and reserved characters removed | `test_file_names_are_sanitised` | Closed |
| G6 | Oversized uploads | 10 MB limit checked in the app and by `MAX_CONTENT_LENGTH` | `test_oversized_upload_is_refused` | Closed |
| G7 | Malware inside an otherwise valid PDF/Office file | Not detected | — | **Accepted**: no AV engine in a free-tier deployment; files are never opened server-side, are served as attachments, and the recipient's endpoint protection applies |

## H. Administrators and insiders

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| H1 | Admin downloads a salary letter | Admin role has no document rights | `test_administrator_cannot_read_any_document_content` | Closed |
| H2 | Admin creates an owner account, transfers a document to it, logs in as it | Possible: admins control identities. Every step is audited and raises alerts (`ownership_transfer`, new account), and transfer requires a written reason | `test_transfer_only_to_active_owners_and_requires_reason`, `test_new_admin_raises_an_alert` | **Accepted** with detection. Fix needs two-person approval for transfers; out of scope for a week |
| H3 | Admin promotes a friend to admin | Allowed, alerted as `new_admin` | `test_new_admin_raises_an_alert` | Mitigated |
| H4 | Admin locks out the last administrator | Cannot change own role or deactivate self | `test_admin_cannot_lock_themselves_out` | Closed |
| H5 | Owner demoted to viewer still "owns" documents | Demotion blocked until documents are transferred | `test_owner_with_documents_cannot_be_demoted_until_transfer` | Closed |
| H6 | Leaver downloads everything before leaving | Alert `leaver_downloads` when someone deactivated had downloads in the prior 7 days; `bulk_download` alert | `test_leaver_download_pattern_raises_an_alert` | Mitigated (detection, not prevention) |
| H7 | Viewer probes many document IDs | Every refusal logged; `access_probing` alert at 5 refusals/hour | `test_probing_raises_an_alert` | Mitigated |
| H8 | Shared demo: one judge deactivates/resets accounts the next judge needs, or purges/transfers seed documents | `TV_DEMO_MODE` protects seeded accounts (role, status, password) and seeded documents (purge, transfer). Grants on seed documents can still be changed, so revocation can be tested on them | `test_demo_mode_protects_shared_demo_accounts_and_seed_documents` | Closed for the demo; flag is off in a real deployment |
| H9 | An owner is deactivated; their documents are orphaned | Existing grants keep working (business continuity); the admin document list flags "owner deactivated" and the admin transfers ownership | — | Accepted by design |

## I. The AI-assisted suggestion feature

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| I1 | The machine widens access on its own | Suggestions are read-only; only `PUT /grants` by the owner creates a grant | `test_suggestions_are_explainable_and_never_grant_by_themselves` | Closed |
| I2 | Grant falsely labelled "from suggestion" to launder a decision | Server recomputes and records the suggestion it actually made | `test_grant_cannot_be_falsely_labelled_as_suggested` | Closed |
| I3 | Suggestion and decision not on record | `suggestion.shown`, `grant.set` with `source=suggestion` and reasons, `suggestion.dismissed` | `test_accepting_a_suggestion_is_a_recorded_human_decision`, `test_dismissal_is_recorded` | Closed |
| I4 | Document metadata sent to an external LLM | Deliberately rule-based and local; nothing leaves the system | — | Closed by design |
| I5 | Suggestion leaks who has access to the owner's *other* documents | Only the owner sees suggestions, and only about people they themselves already shared with | — | Accepted (it is the owner's own information) |
| I6 | Suggesting admins or deactivated people | Excluded | `test_suggestions_never_include_admins_or_inactive_people` | Closed |

## J. Availability, deployment and supply chain

| # | Threat | What stops it | Test | Status |
|---|---|---|---|---|
| J1 | Request floods / upload spam by a logged-in user | Upload size cap; login throttling | — | **Accepted**: no global rate limiter or per-user quota (free-tier hosting; a reverse proxy rate limit is the right layer) |
| J2 | Stack traces or SQL in error responses | Uniform JSON errors with a request ID; details only in server logs | `test_errors_do_not_leak_internals` | Closed |
| J3 | Debug mode / dev keys in production | `TV_ENV=production` refuses missing keys and SQLite; debug never enabled | `config.load_settings` | Closed |
| J4 | Vulnerable dependency | Exact pins; `pip-audit` in CI | CI job `dependency-audit` | Mitigated |
| J5 | Container breakout impact | Non-root user; app code read-only in the image | Dockerfile | Mitigated |
| J6 | Free-tier database expires / is lost | Documented; `verify-audit` and backups are ops tasks | — | Accepted for a demo |

## What I deliberately did not build, and why

- **Anonymous share links.** A link is a bearer credential that can be forwarded, cannot be tied
  to a person, and undermines "prove who reached it". External people (e.g. Vera, the auditor)
  get a named viewer account instead.
- **Groups and folder inheritance.** The brief's first failure story is "access to a folder to see
  one file, now they can see forty". Per-document grants are more clicks but every grant is
  explicit and auditable. Groups would be my next feature, with membership changes audited and
  evaluated per request.
- **MFA / SSO.** The right fix for C3, but a week is better spent making authorisation airtight.
- **Malware scanning, CDR, OCR/full-text search.** Need infrastructure beyond a free tier; full-text
  search over encrypted content would also need a separately protected index.
- **Key rotation tooling, WORM log export, two-person approval for ownership transfer.** Designed
  for (key IDs, anchors, audited transfers) but not built.

## Mutation check results

`python scripts/mutation_check.py` (SQLite, run before submission):

```
Baseline: running the suite unmodified...
  killed   policy: no grant treated as read access
  killed   policy: action not checked against permission
  killed   policy: inactive accounts not refused
  killed   policy: trashed documents visible to grantees
  killed   policy: grant for another user/document accepted
  killed   policy: trash restricts owner actions
  killed   load_document: decision ignored
  killed   load_document: refusal not audited
  killed   load_document: grant looked up for any user
  killed   search: listing not scoped to grants
  killed   categories: facet list not scoped
  killed   upload: role check removed
  killed   download: integrity check removed
  killed   sessions: inactive user keeps session
  killed   sessions: idle timeout ignored
  killed   sessions: logout does not delete server session
  killed   api: CSRF token not checked
  killed   api: Origin not checked
  killed   api: role gate removed
  killed   api: temporary password not enforced
  killed   api: unknown JSON fields accepted
  killed   admin: deactivation keeps sessions
  killed   admin: reset password keeps sessions
  killed   admin: demo accounts unprotected
  killed   admin: demo seed documents transferable
  killed   documents: demo seed documents purgeable
  killed   sharing: suggestion label not verified
  killed   sharing: inactive grantee accepted
  killed   auth: brute-force throttle removed
  killed   auth: deactivated users can log in
  killed   audit: chain not keyed (plain hash)
  killed   audit: sequence gaps not detected
  killed   audit: checkpoints not compared
  killed   db: append-only triggers missing (sqlite)
  killed   headers: download cacheable
  killed   download: served inline
  killed   validation: PDF active content allowed
  killed   validation: extension/content mismatch allowed
  killed   validation: macro-enabled Office allowed

39/39 mutants killed.
```
