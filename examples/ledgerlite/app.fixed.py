"""LedgerLite -- a tiny invoicing API.

A deliberately realistic small backend used to exercise the `paranoid` /hack-me
workflow. Standard library only. Run it and it serves on 127.0.0.1:8071 with a
fresh in-memory database seeded on every start.

    python3 app.py

Dev/test accounts (also printed at startup):
    alice  token: tok_alice   (regular user, owns invoice 101)
    bob    token: tok_bob     (regular user, owns invoice 102)
    admin  token: tok_admin   (admin,        owns invoice 103)

Authenticate by sending the header:  X-Session-Token: <token>
"""
import json
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

HOST, PORT = "127.0.0.1", 8071

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.row_factory = sqlite3.Row


def seed():
    DB.executescript(
        """
        CREATE TABLE users (
          id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT,
          password TEXT, is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE invoices (
          id INTEGER PRIMARY KEY, owner_id INTEGER, amount_cents INTEGER, memo TEXT
        );
        CREATE TABLE sessions (token TEXT PRIMARY KEY, user_id INTEGER);
        """
    )
    DB.executemany(
        "INSERT INTO users VALUES (?,?,?,?,?)",
        [
            (1, "alice@example.com", "Alice", "alicepw", 0),
            (2, "bob@example.com", "Bob", "bobpw", 0),
            (3, "admin@example.com", "Admin", "adminpw", 1),
        ],
    )
    DB.executemany(
        "INSERT INTO invoices VALUES (?,?,?,?)",
        [
            (101, 1, 4200, "Alice: web design"),
            (102, 2, 9900, "Bob: consulting"),
            (103, 3, 500, "Admin: coffee"),
        ],
    )
    DB.executemany(
        "INSERT INTO sessions VALUES (?,?)",
        [("tok_alice", 1), ("tok_bob", 2), ("tok_admin", 3)],
    )
    DB.commit()


def user_for(token):
    if not token:
        return None
    row = DB.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (token,),
    ).fetchone()
    return row


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # keep the console quiet

    # -- helpers ------------------------------------------------------------
    def _send(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _token(self):
        return self.headers.get("X-Session-Token")

    # -- routing ------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path, qs = u.path, parse_qs(u.query)

        if path == "/health":
            return self._send(200, {"ok": True, "service": "ledgerlite"})

        m = re.fullmatch(r"/invoices/(\d+)", path)
        if m:
            me = user_for(self._token())
            if not me:
                return self._send(401, {"error": "login required"})
            row = DB.execute(
                "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ?",
                (int(m.group(1)),),
            ).fetchone()
            # Object-level authorization: only the owner (or an admin) may read an
            # invoice. Treat "not yours" like "not found" so we don't leak existence.
            if not row or (row["owner_id"] != me["id"] and not me["is_admin"]):
                return self._send(404, {"error": "not found"})
            return self._send(200, dict(row))

        if path == "/invoices":
            me = user_for(self._token())
            if not me:
                return self._send(401, {"error": "login required"})
            rows = DB.execute(
                "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE owner_id = ?",
                (me["id"],),
            ).fetchall()
            return self._send(200, [dict(r) for r in rows])

        if path == "/admin/users":
            me = user_for(self._token())
            if not me:
                return self._send(401, {"error": "login required"})
            # Function-level authorization: this is an admin-only endpoint.
            if not me["is_admin"]:
                return self._send(403, {"error": "admin only"})
            rows = DB.execute("SELECT id, email, name, is_admin FROM users").fetchall()
            return self._send(200, [dict(r) for r in rows])

        if path == "/search":
            me = user_for(self._token())
            if not me:
                return self._send(401, {"error": "login required"})
            email = (qs.get("email") or [""])[0]
            # Parameterized query: the user-supplied value is bound, never
            # concatenated into SQL, so it cannot alter the query structure.
            try:
                rows = DB.execute(
                    "SELECT id, email, name FROM users WHERE email = ?", (email,)
                ).fetchall()
            except Exception as e:
                return self._send(400, {"error": str(e)})
            return self._send(200, [dict(r) for r in rows])

        return self._send(404, {"error": "no such route"})

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/login":
            b = self._body()
            row = DB.execute(
                "SELECT * FROM users WHERE email = ? AND password = ?",
                (b.get("email"), b.get("password")),
            ).fetchone()
            if not row:
                return self._send(401, {"error": "invalid credentials"})
            tok = DB.execute("SELECT token FROM sessions WHERE user_id = ?", (row["id"],)).fetchone()
            return self._send(200, {"token": tok["token"]})

        if path == "/profile":
            me = user_for(self._token())
            if not me:
                return self._send(401, {"error": "login required"})
            fields = self._body()
            # Only self-service profile columns may be updated. This blocks both
            # privilege escalation (e.g. is_admin) via mass assignment and SQL
            # injection through the column name (which is not parameterizable).
            allowed = {"name", "email", "password"}
            if not set(fields).issubset(allowed):
                return self._send(400, {"error": "unknown or forbidden field"})
            for k, v in fields.items():
                DB.execute("UPDATE users SET %s = ? WHERE id = ?" % k, (v, me["id"]))
            DB.commit()
            row = DB.execute(
                "SELECT id, email, name, is_admin FROM users WHERE id = ?", (me["id"],)
            ).fetchone()
            return self._send(200, dict(row))

        return self._send(404, {"error": "no such route"})


def main():
    seed()
    banner = (
        "LedgerLite on http://%s:%d  |  accounts: "
        "alice/tok_alice  bob/tok_bob  admin/tok_admin  "
        "(header: X-Session-Token)" % (HOST, PORT)
    )
    print(banner, flush=True)
    HTTPServer.allow_reuse_address = True
    HTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
