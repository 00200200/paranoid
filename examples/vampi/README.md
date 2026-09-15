# VAmPI — `/hack-me` against an independent, third-party vulnerable app

LedgerLite ([`../ledgerlite`](../ledgerlite)) is our own demo, so it proves the
`/hack-me` **loop** works. This example is the harder claim: pointing `/hack-me`
at an app **we didn't write** and letting it find, prove, patch, and re-verify
real bugs.

The target is [OWASP VAmPI](https://github.com/erev0s/VAmPI) — "The Vulnerable
API," a widely-used intentionally-vulnerable Flask API built around the OWASP API
Security Top 10. We do not vendor its code here; we link it and publish the
receipts.

## What `/hack-me` found

Given only the base URL and the normal `GET /createdb` seed step — and told
nothing about the bugs — it proved six vulnerabilities with live requests, then
closed and re-verified each:

| # | Finding | OWASP API | Severity | Status |
|---|---------|-----------|----------|--------|
| 1 | Unauthenticated `/users/v1/_debug` dumps every password | API3/API5 | Critical | Fixed → 401/403 |
| 2 | Read any user's private book secret | API1 (BOLA) | High | Fixed → 404 |
| 3 | Register with `admin:true` → privilege escalation | API6 | High | Fixed → admin=false |
| 4 | Change any user's password (account takeover) | API1 (BOLA) | Critical | Fixed → victim untouched |
| 5 | SQL injection in user lookup (UNION-dumps passwords) | API8 | Critical | Fixed → 404 |
| 6 | Werkzeug debugger + stack traces exposed | API7 | High | Fixed → clean errors |

The full walkthrough — exact exploit requests, responses (incl. the admin
password exfiltrated via SQLi), fixes, and re-verification — is in
[`HACKME_REPORT.md`](HACKME_REPORT.md).

## The interesting part

VAmPI has a global `vulnerable=1|0` switch. Flipping it to "secure" closed **four**
of the six — but the critical unauthenticated password dump stayed wide open,
because that endpoint was never wired into the switch. A single "secure mode" flag
is not the same as being secure, and `/hack-me` caught the gap by replaying every
exploit rather than trusting the flag.

## Reproduce

```bash
git clone https://github.com/erev0s/VAmPI && cd VAmPI
pip install -r requirements.txt
vulnerable=1 python3 app.py              # http://127.0.0.1:5000
curl -s http://127.0.0.1:5000/createdb   # seed demo users
# run /hack-me (../../commands/hack-me.md) against http://127.0.0.1:5000
```

Guardrails, as always: your own / authorized target, localhost only,
non-destructive proofs.
