# LedgerLite — Penetration Test Report

**Target:** `http://127.0.0.1:8071` (local, authorized test)
**Source:** `examples/ledgerlite/app.py` (Python stdlib HTTP server, in-memory SQLite, reseeded on every start)
**Date:** 2026-09-15
**Method:** black-box probing of the running app; code read only to confirm root cause and write fixes. Every finding below is proven with a live HTTP request/response, then patched, then re-verified against the same request after restart.

Accounts used: `alice`/`tok_alice` (owns invoice 101), `bob`/`tok_bob` (owns 102), `admin`/`tok_admin` (admin, owns 103).

**Result: 4 vulnerabilities proven and fixed.**

---

## Finding 1 — IDOR: any user can read any invoice

- **Class:** Broken Object-Level Authorization (IDOR / access control) — OWASP A01
- **Severity:** High
- **Endpoint:** `GET /invoices/{id}`

The handler checked only that the caller was *authenticated*, never that the invoice belonged to them. Any logged-in user could read every other user's invoice (amounts + memos) by iterating IDs.

### Exploit
Alice (owner of 101 only) reads Bob's and the admin's invoices:

```
$ curl -s -H "X-Session-Token: tok_alice" http://127.0.0.1:8071/invoices/102
{"id": 102, "owner_id": 2, "amount_cents": 9900, "memo": "Bob: consulting"}      # HTTP 200

$ curl -s -H "X-Session-Token: tok_alice" http://127.0.0.1:8071/invoices/103
{"id": 103, "owner_id": 3, "amount_cents": 500, "memo": "Admin: coffee"}         # HTTP 200
```

### Fix
Load the caller (`me`) and, after fetching the row, require `row.owner_id == me.id` **or** `me.is_admin`. Non-owners get `404` (so existence isn't leaked). Admins retain full read access.

```python
me = user_for(self._token())
if not me:
    return self._send(401, {"error": "login required"})
row = DB.execute("SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ?", (int(m.group(1)),)).fetchone()
if not row or (row["owner_id"] != me["id"] and not me["is_admin"]):
    return self._send(404, {"error": "not found"})
return self._send(200, dict(row))
```

### Re-verify
```
$ curl -s -H "X-Session-Token: tok_alice" http://127.0.0.1:8071/invoices/102
{"error": "not found"}        # HTTP 404

$ curl -s -H "X-Session-Token: tok_alice" http://127.0.0.1:8071/invoices/103
{"error": "not found"}        # HTTP 404
```
Happy path preserved — Alice still reads her own invoice, admin still reads any:
```
$ curl -s -H "X-Session-Token: tok_alice" http://127.0.0.1:8071/invoices/101
{"id": 101, "owner_id": 1, "amount_cents": 4200, "memo": "Alice: web design"}    # HTTP 200
$ curl -s -H "X-Session-Token: tok_admin" http://127.0.0.1:8071/invoices/102
{"id": 102, "owner_id": 2, "amount_cents": 9900, "memo": "Bob: consulting"}      # HTTP 200
```

---

## Finding 2 — Missing function-level authorization on `/admin/users`

- **Class:** Broken Function-Level Authorization (access control) — OWASP A01
- **Severity:** Medium
- **Endpoint:** `GET /admin/users`

The "admin" endpoint checked authentication but never checked `is_admin`. Any regular user could dump the full user directory (emails and admin flags of every account).

### Exploit
Non-admin Alice lists all users:

```
$ curl -s -H "X-Session-Token: tok_alice" http://127.0.0.1:8071/admin/users
[{"id": 1, "email": "alice@example.com", "name": "Alice", "is_admin": 0},
 {"id": 2, "email": "bob@example.com", "name": "Bob", "is_admin": 0},
 {"id": 3, "email": "admin@example.com", "name": "Admin", "is_admin": 1}]        # HTTP 200
```

### Fix
Require admin after authentication:

```python
if not me["is_admin"]:
    return self._send(403, {"error": "admin only"})
```

### Re-verify
```
$ curl -s -H "X-Session-Token: tok_alice" http://127.0.0.1:8071/admin/users
{"error": "admin only"}        # HTTP 403
```
Happy path preserved — the real admin still lists users:
```
$ curl -s -H "X-Session-Token: tok_admin" http://127.0.0.1:8071/admin/users
[{"id": 1, ...}, {"id": 2, ...}, {"id": 3, ..., "is_admin": 1}]                  # HTTP 200
```

---

## Finding 3 — SQL injection in `/search`

- **Class:** SQL Injection — OWASP A03
- **Severity:** High
- **Endpoint:** `GET /search?email=...`

The `email` parameter was concatenated directly into the query
(`"... WHERE email = '%s'" % email`). This allows arbitrary read of the database, including plaintext passwords via a `UNION`.

### Exploit
Boolean bypass returns every user (not just an exact match):
```
$ curl -s -G -H "X-Session-Token: tok_alice" --data-urlencode "email=' OR '1'='1" http://127.0.0.1:8071/search
[{"id": 1, "email": "alice@example.com", "name": "Alice"},
 {"id": 2, "email": "bob@example.com", "name": "Bob"},
 {"id": 3, "email": "admin@example.com", "name": "Admin"}]                       # HTTP 200
```
UNION exfiltrates plaintext passwords into the `name` column (full account takeover, incl. admin):
```
$ curl -s -G -H "X-Session-Token: tok_alice" --data-urlencode "email=' UNION SELECT id, email, password FROM users -- " http://127.0.0.1:8071/search
[{"id": 1, "email": "alice@example.com", "name": "alicepw"},
 {"id": 2, "email": "bob@example.com", "name": "bobpw"},
 {"id": 3, "email": "admin@example.com", "name": "adminpw"}]                     # HTTP 200
```

### Fix
Use a parameterized (bound) query so input can never alter query structure:

```python
rows = DB.execute("SELECT id, email, name FROM users WHERE email = ?", (email,)).fetchall()
```

### Re-verify
Both payloads are now treated as literal strings — no row matches, nothing leaks:
```
$ curl -s -G -H "X-Session-Token: tok_alice" --data-urlencode "email=' OR '1'='1" http://127.0.0.1:8071/search
[]        # HTTP 200

$ curl -s -G -H "X-Session-Token: tok_alice" --data-urlencode "email=' UNION SELECT id, email, password FROM users -- " http://127.0.0.1:8071/search
[]        # HTTP 200
```
Happy path preserved — legitimate exact-match search still works:
```
$ curl -s -G -H "X-Session-Token: tok_alice" --data-urlencode "email=bob@example.com" http://127.0.0.1:8071/search
[{"id": 2, "email": "bob@example.com", "name": "Bob"}]                           # HTTP 200
```

---

## Finding 4 — Mass assignment / privilege escalation on `/profile`

- **Class:** Mass Assignment + request-body trust (with column-name SQL injection) — OWASP A01 / A03
- **Severity:** High
- **Endpoint:** `POST /profile`

The handler looped over **every** key in the JSON body and interpolated it as a column name:
`UPDATE users SET %s = ? WHERE id = ?`. A user could therefore set any column on their own row — including `is_admin` — and could also inject SQL through the (non-parameterizable) column name.

### Exploit
Alice escalates herself to admin:
```
$ curl -s -X POST -H "X-Session-Token: tok_alice" -d '{"is_admin":1}' http://127.0.0.1:8071/profile
{"id": 1, "email": "alice@example.com", "name": "Alice A", "is_admin": 1}        # HTTP 200
```
The change persists (confirmed via admin listing — Alice now `is_admin: 1`):
```
$ curl -s -H "X-Session-Token: tok_admin" http://127.0.0.1:8071/admin/users
[{"id": 1, ..., "is_admin": 1}, ...]
```
The same interpolation is a SQL-injection sink: a crafted key
(`"name = 1, is_admin = 1 -- "`) is spliced straight into the `UPDATE` and, in the original code, corrupted the statement (server-side `sqlite3.ProgrammingError`, connection dropped / HTTP 000).

### Fix
Whitelist the self-service columns; reject any other/unknown field with `400`. This closes both the privilege escalation and the column-name injection.

```python
allowed = {"name", "email", "password"}
if not set(fields).issubset(allowed):
    return self._send(400, {"error": "unknown or forbidden field"})
```

### Re-verify
```
$ curl -s -X POST -H "X-Session-Token: tok_alice" -d '{"is_admin":1}' http://127.0.0.1:8071/profile
{"error": "unknown or forbidden field"}        # HTTP 400

# alice is still NOT admin afterwards:
$ curl -s -H "X-Session-Token: tok_admin" http://127.0.0.1:8071/admin/users
[{"id": 1, "email": "alice@example.com", "name": "Alice A", "is_admin": 0}, ...] # HTTP 200

# column-name injection attempt is also rejected:
$ curl -s -X POST -H "X-Session-Token: tok_alice" -d '{"name = 1, is_admin = 1 -- ":"x"}' http://127.0.0.1:8071/profile
{"error": "unknown or forbidden field"}        # HTTP 400
```
Happy path preserved — a legitimate profile update still works:
```
$ curl -s -X POST -H "X-Session-Token: tok_alice" -d '{"name":"Alice A"}' http://127.0.0.1:8071/profile
{"id": 1, "email": "alice@example.com", "name": "Alice A", "is_admin": 0}        # HTTP 200
```

---

## Summary

| # | Finding | Class | Severity | Status |
|---|---------|-------|----------|--------|
| 1 | Any user can read any invoice (`GET /invoices/{id}`) | Broken object-level auth (IDOR) | High | Fixed |
| 2 | `/admin/users` open to any authenticated user | Broken function-level auth | Medium | Fixed |
| 3 | SQL injection in `/search?email=` (dumps passwords) | SQL injection | High | Fixed |
| 4 | Mass assignment → privilege escalation on `/profile` (+ column-name SQLi) | Mass assignment / request-body trust | High | Fixed |

All four were re-verified blocked after the fix (404 / 403 / empty result / 400), and all legitimate happy-path requests (own-invoice read, own list, admin listing, admin cross-read, exact-match search, legitimate profile update, login) still return `200` with correct data. The server reseeds a fresh in-memory DB on each restart, so re-verification ran against clean state.

### Suspected / noted, not separately patched

- **Plaintext password storage (High, design).** Passwords are stored and compared in cleartext (`alicepw`, `bobpw`, `adminpw`) — proven by the Finding 3 UNION dump. Not fixed as a separate item because the remote exfiltration channel (the SQLi) is now closed, and proper remediation (salted password hashing) requires reworking `/login` and the seed data, which is beyond a minimal, behavior-preserving patch. **Recommendation:** hash passwords (e.g. PBKDF2/`hashlib.scrypt`) and compare with a constant-time check.
- **Static, guessable session tokens.** Tokens are literals (`tok_alice`, …) tied 1:1 to users. This is test-seed convenience rather than a runtime flaw in the handler logic, but in production tokens must be long, random, and rotated. Not exploitable beyond what the accounts already grant, so nothing to "prove" here.
- **No rate limiting / lockout on `/login`.** Enables credential brute force. Noted as hardening; not demonstrated as a distinct exploit.
