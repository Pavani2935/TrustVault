# Five-minute demo script

Use two browser windows: a normal one and a private one, so two people are signed in at once.

| Time | Show | Say |
|---|---|---|
| 0:00–0:30 | README, roles table | "Three roles. The admin manages people and evidence but cannot open documents. Owners share with named people. Viewers see only what was shared with them." |
| 0:30–1:15 | Sign in as **olivia** → Upload a PDF, category HR | "Content is checked, not the name. Each version gets its own AES-256-GCM key." Try uploading a `.exe` renamed to `.pdf` → refused. |
| 1:15–2:00 | Private window: **victor** → paste the new document's URL | 404, same as a random ID. "The server decides on every request; the button was never the protection." Then show the same with `curl` on `/download`. |
| 2:00–2:40 | olivia → Who has access → grant victor **read** | victor refreshes: opens and downloads it. |
| 2:40–3:20 | olivia → Revoke victor (victor stays signed in) | victor clicks Download again → 404. "No link or token was ever issued that could outlive this check." |
| 3:20–3:50 | olivia → "Who reached this document" | The view, the download, the refused attempt before the grant, the grant and the revoke, each with time and IP. |
| 3:50–4:30 | **admin** → Activity & alerts | "Probing" alert from victor's refused attempts. Click **Verify audit chain**: intact. Explain: append-only triggers, HMAC chain with a key not in the DB, checkpoints, log copy. |
| 4:30–5:00 | Terminal: `python -m pytest` and `python scripts/mutation_check.py policy` | "Every check in THREATS.md has a test, and removing a check makes the tests fail. Known gaps are written down in THREATS.md." |
