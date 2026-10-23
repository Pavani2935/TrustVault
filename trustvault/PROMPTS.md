# PROMPTS.md: how I used AI, and where it was wrong

I used AI assistants throughout: first to generate a starter, then to review it and rebuild
the system. The rule I worked by: **AI output is a proposal; a test decides.** Every entry
below is a case where the output looked plausible and was wrong, and what I did about it.

> Commit links: fill in each `Commit:` line with the GitHub URL of the commit that contains the fix.

---

## 2026-10-21: Review of the AI-generated starter (authorisation, sessions, audit)

**Asked:** "Here is a starter implementation of TrustVault. Identify its flaws against the brief
and rebuild it to an enterprise standard."

**What the starter was:** a single-file Flask app with SQLite, Fernet-encrypted files, a
`require_document` decorator, a SHA-256 audit chain and six tests. It looked secure and
its README said so.

**What was wrong, specifically:**
1. `app.secret_key = os.environ.get("TRUSTVAULT_SECRET", "dev-only-change-me")`. If the variable
   is missing, anyone can sign a session cookie with `uid` of the admin. The app starts happily.
2. Flask's default signed-cookie session. Logging out only deletes the browser's copy; a copied
   cookie stays valid forever. There was also **no way to deactivate a user**, the brief's
   "someone leaves the company and their link still works" case.
3. Admin was a superuser for documents (`if user["role"] == "admin": return "owner"`), which breaks
   "only someone who was granted it".
4. The category dropdown was built from `SELECT DISTINCT category FROM documents`: every user
   learned every category in the system.
5. No CSRF protection on the grant/revoke/delete forms.
6. Audit chain: plain SHA-256 that anyone with DB write access can recompute; head read and insert
   not locked (two workers fork the chain); audit committed separately from the action; the full
   table loaded into memory on every admin page view; tail truncation undetectable.
7. File validation trusted the extension and the browser's MIME type; key file stored on the same
   disk as the ciphertext.
8. Tests: removing the checks in `grant_access` or `revoke_access` left every test green.

**What I did instead:** rebuilt around one policy function (`security/policy.py::decide`) and one
loader (`load_document`) that every route must use; server-side sessions; admin with no document
rights; scoped facets; CSRF + Origin checks; keyed, gap-free, lock-protected, same-transaction audit
ledger with DB triggers and checkpoints; envelope encryption; content-based validation; a test
matrix over every person × document × endpoint; and `scripts/mutation_check.py` that removes each
check and proves a test fails.

Commit: _add link_

---

## 2026-10-21: Audit sequence numbers (audit trail)

**Asked:** design gap detection for the audit trail ("if a row is deleted, verification must say so").

**Produced:** use the database's auto-increment `id` and flag any missing number as a deleted event.

**What was wrong:** PostgreSQL sequences skip numbers whenever a transaction rolls back (e.g. an
upload that fails validation after the insert). Every failed upload would look like evidence
tampering, so admins would learn to ignore the alarm, which is worse than no alarm.

**What I did instead:** `seq` is assigned by the application as head + 1 while holding a
transaction-scoped lock (`pg_advisory_xact_lock` on PostgreSQL, `BEGIN IMMEDIATE` on SQLite), in the
same transaction as the action. A rolled-back action rolls back its audit row and its number, so
gaps really mean deletion. `test_concurrent_requests_keep_the_chain_gap_free` runs parallel
downloads and checks `seq == 1..n`; `test_deleted_event_is_detected` deletes a row.

Commit: _add link_

---

## 2026-10-21: Login throttling counted with a LIKE on JSON (authentication)

**Asked:** throttle failed logins per account and IP without a separate table, using the audit trail.

**Produced:** `details LIKE '%"attempted_username":"<username>"%'` to count failures for a username.

**What was wrong:** the username is attacker-controlled. `%` and `_` are LIKE wildcards, so an
attacker could send usernames that match (or avoid matching) other people's failure counts, both
evading the throttle and inflating someone else's. It also scanned a text column.

**What I did instead:** failed logins record the claimed username in the indexed `actor_username`
column (sanitised, max 64 chars) and the throttle uses exact equality on it plus `ip`.
`test_brute_force_is_throttled_per_account_and_ip` and the mutant "auth: brute-force throttle
removed" cover it.

Commit: _add link_

---

## 2026-10-21: A trigger test that could never fail (audit trail)

**Asked:** a test proving the database refuses `UPDATE` on audit rows.

**Produced:** `UPDATE audit_events SET outcome='success' WHERE outcome='denied'` inside
`pytest.raises(...)`.

**What was wrong:** the seeded database has no denied events, so the statement matched zero
rows, the row-level trigger never fired, and the test would have passed even with no trigger at
all. (It actually failed with "DID NOT RAISE", which is how I noticed.)

**What I did instead:** target a row that always exists (`WHERE seq = 1`), and added the mutant
"db: append-only triggers missing" to `scripts/mutation_check.py` so the suite must fail if the
triggers are removed.

Commit: _add link_

---

## 2026-10-21: Download hardening silently overwritten (access to file bytes)

**Asked:** serve downloads safely so an uploaded file can never run in our origin.

**Produced:** the download route set `Content-Security-Policy: sandbox; default-src 'none'`, and a
global `after_request` hook set the site-wide CSP.

**What was wrong:** the global hook ran last and *replaced* the download's stricter policy, so
downloads were served without `sandbox`. Each piece looked right alone.

**What I did instead:** the hook uses `setdefault` so a route-specific policy wins;
`test_downloads_are_sandboxed_attachments` checks the header on a real download.

Commit: _add link_

---

## 2026-10-21: The mutation check found a check nothing tested (file integrity)

**Asked:** a script that removes each security check in turn and runs the suite, mirroring what
the judges said they would do ("take one authorisation check out and run your tests").

**Produced:** `scripts/mutation_check.py` with 37 mutants. First full run: 36 killed, **1 survived**:
removing the SHA-256 comparison after decryption in `download()` left every test green.

**What was wrong:** the AI-written tests only exercised integrity through AES-GCM (swapping
ciphertext), which fails before the hash comparison is reached. The stored hash is what the audit
trail and the `X-Content-SHA256` header promise to the recipient; if someone edits it in the
database, the app would have served the file with a false fingerprint and logged the false one.

**What I did instead:** added `test_tampered_hash_metadata_is_detected_not_served`, which edits the
stored hash directly in the database and expects a refused download (500 `integrity_error`) and an
audit event with outcome `error`. Re-ran the mutant: killed.

The second run found another survivor: removing the *sequence-gap* check in audit verification
still passed, because deleting a middle row also breaks the hash chain, and my test accepted
either message. Detection was fine, but the report would only say "chain broken at #6" instead of
"event #5 is missing", and that is the sentence an investigator needs. I tightened
`test_deleted_event_is_detected` to require the exact gap message.

Commit: _add link_

---

## 2026-10-21: Pinned dependencies with known vulnerabilities (supply chain)

**Asked:** pin exact dependency versions for a reproducible build.

**Produced:** `cryptography==44.0.3`, `argon2-cffi==23.1.0`: versions that existed in the model's
training data, presented as current.

**What was wrong:** `pip-audit -r requirements.txt` reported six published advisories against
`cryptography` 44.0.3 (fixed in 46.x to 50.x). The library that does all of the file encryption
was the one with the advisories.

**What I did instead:** upgraded to `cryptography==50.0.2` and `argon2-cffi==25.1.0`, re-ran the full
suite on SQLite and PostgreSQL, and added `pip-audit` as a CI job so a newly published advisory fails
the build instead of waiting for someone to notice.

Commit: _add link_

---

## 2026-10-21: Tests that encoded wrong expectations

Three generated tests failed, and in each case the **test** was wrong, not the code. Worth
recording because the tempting fix was to change the code until the test passed:

- A password-change test used `Victor-Own#Pass9` for user `victor`; the policy correctly rejects
  passwords containing the username. Changed the test's password, kept the policy.
- A malformed-ID test expected `..%2F..%2Fetc%2Fpasswd` to produce an audited refusal. Encoded
  slashes never match a document route at all (plain 404, nothing reached), so there is nothing to
  audit. Kept the 404 assertion, scoped the audit assertion to IDs that reach the route.
- A suggestions test expected `vera` to be the only suggestion; `olivia` also holds Oscar's other
  Audit document, so both are correct suggestions with equal scores.

Commit: _add link_

---

## Reusable context I gave the AI for every change

```
You are changing TrustVault, a document vault whose security is being attacked by judges.
Rules:
- Every document operation must obtain the document through
  services/documents.py::load_document(actor, id, Action.X). Never query Document directly
  in a route or service that returns data to a caller.
- The authorisation decision lives only in security/policy.py::decide(). Do not add role
  shortcuts (especially "admin can do anything").
- Treat IDs, file names, JSON fields, headers and query strings as attacker-controlled.
  Reject unknown JSON fields.
- Write the audit event in the same transaction as the change; record refusals too.
- Nothing may outlive a revocation: no signed URLs, tokens or caches of decisions.
- For every check you add, add a test that fails if the check is removed, and add the check
  to scripts/mutation_check.py.
- Say explicitly what the change does NOT protect against, for THREATS.md.
```

## Review checklist I ran on AI output

1. Which line makes the authorisation decision, and what happens if I delete it? (Run the mutant.)
2. Can the same data be reached through another route: search, list, facets, versions, HEAD, activity?
3. Does a refusal leave an audit row? Is it committed even though the request fails?
4. If access is revoked between two requests, does anything issued earlier still work?
5. Does the test touch real rows / real headers, or could it pass vacuously?
