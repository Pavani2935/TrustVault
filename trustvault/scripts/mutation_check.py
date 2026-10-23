#!/usr/bin/env python3
"""Remove security checks one at a time and prove the test suite notices.

The challenge brief says the judges will take one authorisation check out of the code
and run the tests. This script does exactly that for every check we rely on: each
"mutant" below disables one check, runs the suite, and the mutant must be KILLED
(at least one test fails). A SURVIVING mutant means a check is not really tested.

    python scripts/mutation_check.py            # all mutants
    python scripts/mutation_check.py policy     # only mutants whose name contains "policy"

Exit code 0 only if every mutant is killed. The working tree is always restored.
"""
from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (name, file, original snippet, mutated snippet)
MUTANTS = [
    ("policy: no grant treated as read access", "trustvault/security/policy.py",
     'return Decision(False, None, "no grant for this document")', 'permission = "read"'),
    ("policy: action not checked against permission", "trustvault/security/policy.py",
     "if action not in allowed_actions:", "if False:"),
    ("policy: inactive accounts not refused", "trustvault/security/policy.py",
     "if actor is None or not actor.is_active or document is None:", "if actor is None or document is None:"),
    ("policy: trashed documents visible to grantees", "trustvault/security/policy.py",
     "    if document.deleted_at is not None:\n        return None\n", ""),
    ("policy: grant for another user/document accepted", "trustvault/security/policy.py",
     "if grant is not None and grant.user_id == actor.id and grant.document_id == document.id:", "if grant is not None:"),
    ("policy: trash restricts owner actions", "trustvault/security/policy.py",
     "allowed_actions = allowed_actions & TRASH_OWNER_ACTIONS", "pass"),
    ("load_document: decision ignored", "trustvault/services/documents.py",
     "    if not decision.allowed:\n        audit.record(db, action=f\"document.{action.value}\"",
     "    if False:\n        audit.record(db, action=f\"document.{action.value}\""),
    ("load_document: refusal not audited", "trustvault/services/documents.py",
     "        audit.record(db, action=f\"document.{action.value}\", outcome=\"denied\", actor=actor,\n"
     "                     document_id=str(doc_id)[:64], details={\"reason\": decision.reason})\n",
     ""),
    ("load_document: grant looked up for any user", "trustvault/services/documents.py",
     "select(Grant).where(Grant.document_id == document.id, Grant.user_id == actor.id)",
     "select(Grant).where(Grant.document_id == document.id).limit(1)"),
    ("search: listing not scoped to grants", "trustvault/services/documents.py",
     "return and_(Document.deleted_at.is_(None), or_(Document.owner_id == actor.id, granted))",
     "return and_(Document.deleted_at.is_(None))"),
    ("categories: facet list not scoped", "trustvault/services/documents.py",
     "select(Document.category).where(accessible_filter(actor))", "select(Document.category)"),
    ("upload: role check removed", "trustvault/services/documents.py",
     'if actor.role != "owner":', "if False:"),
    ("download: integrity check removed", "trustvault/services/documents.py",
     "if hashlib.sha256(plaintext).hexdigest() != version.sha256:", "if False:"),
    ("sessions: inactive user keeps session", "trustvault/security/sessions.py",
     "if user is None or not user.is_active:", "if user is None:"),
    ("sessions: idle timeout ignored", "trustvault/security/sessions.py",
     "if now > _aware(row.expires_at) or now > idle_limit:", "if now > _aware(row.expires_at):"),
    ("sessions: logout does not delete server session", "trustvault/security/sessions.py",
     "        db.execute(delete(Session).where(Session.token_hash == _hash(token)))", "        pass"),
    ("api: CSRF token not checked", "trustvault/api/__init__.py",
     'if g.session is not None and not sessions.csrf_ok(g.session, request.headers.get("X-CSRF-Token")):', "if False:"),
    ("api: Origin not checked", "trustvault/api/__init__.py",
     'if f"{parts.scheme}://{parts.netloc}" != expected:', "if False:"),
    ("api: role gate removed", "trustvault/api/__init__.py",
     "if g.user.role not in roles:", "if False:"),
    ("api: temporary password not enforced", "trustvault/api/__init__.py",
     "if g.user.must_change_password and request.endpoint not in PASSWORD_CHANGE_ALLOWED:", "if False:"),
    ("api: unknown JSON fields accepted", "trustvault/api/__init__.py",
     "    if unknown:\n", "    if False:\n"),
    ("admin: deactivation keeps sessions", "trustvault/services/admin.py",
     "ended = sessions.end_all_sessions(db, target.id) if end_sessions else 0", "ended = 0"),
    ("admin: reset password keeps sessions", "trustvault/services/admin.py",
     "    target.must_change_password = True\n    target.updated_at = utcnow()\n    ended = sessions.end_all_sessions(db, target.id)",
     "    target.must_change_password = True\n    target.updated_at = utcnow()\n    ended = 0"),
    ("admin: demo accounts unprotected", "trustvault/services/admin.py",
     "if _settings().demo_mode and target.is_demo_account:", "if False:"),
    ("admin: demo seed documents transferable", "trustvault/services/admin.py",
     "    if _settings().demo_mode and doc.is_demo_seed:\n        raise ApiError(403, \"demo_protected\",\n                       \"Seeded demo documents cannot be transferred",
     "    if False:\n        raise ApiError(403, \"demo_protected\",\n                       \"Seeded demo documents cannot be transferred"),
    ("documents: demo seed documents purgeable", "trustvault/services/documents.py",
     "if _settings().demo_mode and doc.is_demo_seed:", "if False:"),
    ("sharing: suggestion label not verified", "trustvault/services/sharing.py",
     "        if target.id not in current:\n            raise ValidationError(\"this person is not among the current suggestions\", \"source\")",
     "        if target.id not in current:\n            current[target.id] = {\"score\": 0, \"reasons\": []}"),
    ("sharing: inactive grantee accepted", "trustvault/services/sharing.py",
     "if target is None or not target.is_active:", "if target is None:"),
    ("auth: brute-force throttle removed", "trustvault/services/auth.py",
     "if per_ip >= s.login_max_failures_per_ip or per_user_ip >= s.login_max_failures_per_user_ip:", "if False:"),
    ("auth: deactivated users can log in", "trustvault/services/auth.py",
     "if not ok or not user.is_active:", "if not ok:"),
    ("audit: chain not keyed (plain hash)", "trustvault/audit.py",
     "return hmac.new(key, message, hashlib.sha256).hexdigest()", "return hashlib.sha256(message).hexdigest()"),
    ("audit: sequence gaps not detected", "trustvault/audit.py",
     'problems.append(f"sequence gap: expected #{expected_seq}, found #{ev.seq} (events deleted?)")', "pass"),
    ("audit: checkpoints not compared", "trustvault/audit.py",
     "        if seq > head_seq:", "        if False:"),
    ("db: append-only triggers missing (sqlite)", "trustvault/db.py",
     "    statements = POSTGRES_PROTECTIONS if engine.dialect.name == \"postgresql\" else SQLITE_PROTECTIONS",
     "    statements = []"),
    ("headers: download cacheable", "trustvault/__init__.py",
     'h["Cache-Control"] = "no-store"', 'h["Cache-Control"] = "private, max-age=3600"'),
    ("download: served inline", "trustvault/api/routes_documents.py",
     'f"attachment; filename=', 'f"inline; filename='),
    ("validation: PDF active content allowed", "trustvault/validation.py",
     "if any(marker in data for marker in _PDF_ACTIVE):", "if False:"),
    ("validation: extension/content mismatch allowed", "trustvault/validation.py",
     "if ext not in detected.extensions:", "if False:"),
    ("validation: macro-enabled Office allowed", "trustvault/validation.py",
     'if any(n.lower().endswith("vbaproject.bin") for n in names):', "if False:"),
]


def run_tests() -> bool:
    proc = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                          cwd=ROOT, capture_output=True, text=True)
    return proc.returncode == 0


def _interrupt(signum, frame):  # make `finally` restore the file even on SIGTERM
    raise KeyboardInterrupt


def main() -> int:
    signal.signal(signal.SIGTERM, _interrupt)
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    selected = [m for m in MUTANTS if only in m[0]]
    print("Baseline: running the suite unmodified...", flush=True)
    if not run_tests():
        print("Baseline suite fails; fix that first.")
        return 2
    survivors = []
    for name, rel, old, new in selected:
        path = ROOT / rel
        original = path.read_text()
        count = original.count(old)
        if count != 1:
            print(f"  ERROR    {name}: snippet found {count} times in {rel}")
            survivors.append(name)
            continue
        start = time.time()
        mutated = original.replace(old, new)
        try:
            compile(mutated, str(path), "exec")  # a mutant that does not even compile proves nothing
        except SyntaxError as exc:
            print(f"  INVALID  {name}: {exc}")
            survivors.append(name)
            continue
        try:
            path.write_text(mutated)
            passed = run_tests()
        finally:
            path.write_text(original)
        verdict = "SURVIVED" if passed else "killed"
        print(f"  {verdict:8} {name}  ({time.time() - start:.0f}s)", flush=True)
        if passed:
            survivors.append(name)
    print(f"\n{len(selected) - len(survivors)}/{len(selected)} mutants killed.")
    if survivors:
        print("Surviving (untested) checks:\n  - " + "\n  - ".join(survivors))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
