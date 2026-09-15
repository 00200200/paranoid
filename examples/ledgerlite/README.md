# LedgerLite — a `/hack-me` demo target

A tiny, deliberately vulnerable invoicing API (Python standard library only, no
dependencies) used to demonstrate the `paranoid` **/hack-me** workflow end to
end: find → prove → patch → re-verify, against a real running app.

## Files

- **`app.py`** — the vulnerable app. Run it: `python3 app.py` → serves on
  `http://127.0.0.1:8071`, fresh in-memory DB on every start.
- **`app.fixed.py`** — the same app after `/hack-me` patched it (kept so you can
  diff before/after).
- **`HACKME_REPORT.md`** — the report produced by the run: every finding with the
  exact exploit request, the response proving it, the fix, and the re-verification.

## Reproduce the demo

```bash
python3 app.py            # start the vulnerable app
# then run the /hack-me workflow (see ../../commands/hack-me.md) against
# http://127.0.0.1:8071 with test accounts alice/tok_alice, bob/tok_bob, admin/tok_admin
```

The `/hack-me` agent is given only the app and normal test accounts — **not** any
knowledge of the bugs. It found and closed four, verified live:

| # | Finding | Class | Severity | Status |
|---|---------|-------|----------|--------|
| 1 | Any user can read any invoice (`GET /invoices/{id}`) | Broken object-level auth (IDOR) | High | Fixed → 404 |
| 2 | `/admin/users` open to any authenticated user | Broken function-level auth | Medium | Fixed → 403 |
| 3 | SQL injection in `/search?email=` (dumps passwords) | SQL injection | High | Fixed → `[]` |
| 4 | Mass assignment → privilege escalation on `/profile` | Mass assignment / body trust | High | Fixed → 400 |

Every legitimate request (own-invoice read, own list, admin listing, exact-match
search, legitimate profile update, login) still returns `200` afterward.

## Honest scope

This app was written as a controlled target, so the demo shows the loop *can*
autonomously discover, prove, patch, and re-verify real vulnerability classes in
a running app it wasn't briefed on. It is **not** a claim about third-party code
— for that, run `/hack-me` against an independent intentionally-vulnerable app
(e.g. OWASP Juice Shop) on localhost. Same workflow, same guardrails: your own /
authorized targets, localhost, non-destructive proofs.
