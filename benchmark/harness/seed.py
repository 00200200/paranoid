"""Shared fixture: a fresh, seeded in-memory SQLite DB for every check.

Every task gets an identical database so functional and exploit tests are
deterministic. Tasks import the canonical ids/values below rather than
hard-coding them.
"""
import sqlite3

# canonical fixture facts
ALICE, BOB, ADMIN = 1, 2, 3
ALICE_INVOICE, BOB_INVOICE = 101, 102


def fresh_db():
    """Return a new, seeded sqlite3 connection (row_factory = Row)."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (
          id INTEGER PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          password TEXT NOT NULL,
          is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE invoices (
          id INTEGER PRIMARY KEY,
          owner_id INTEGER NOT NULL,
          amount_cents INTEGER NOT NULL,
          memo TEXT NOT NULL
        );
        CREATE TABLE sessions (
          token TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL
        );
        """
    )
    conn.executemany(
        "INSERT INTO users VALUES (?,?,?,?,?)",
        [
            (ALICE, "alice@example.com", "Alice", "pw_alice", 0),
            (BOB, "bob@example.com", "Bob", "pw_bob", 0),
            (ADMIN, "admin@example.com", "Admin", "pw_admin", 1),
        ],
    )
    conn.executemany(
        "INSERT INTO invoices VALUES (?,?,?,?)",
        [
            (ALICE_INVOICE, ALICE, 4200, "Alice private invoice"),
            (BOB_INVOICE, BOB, 9900, "Bob private invoice"),
        ],
    )
    conn.executemany(
        "INSERT INTO sessions VALUES (?,?)",
        [("sess_alice", ALICE), ("sess_bob", BOB), ("sess_admin", ADMIN)],
    )
    conn.commit()
    return conn


def as_dict(x):
    """Best-effort coerce a solution's return row into a dict (dict / Row / obj)."""
    if x is None:
        return None
    if isinstance(x, dict):
        return x
    try:
        return dict(x)  # sqlite3.Row and other mappings
    except Exception:
        return {k: getattr(x, k) for k in dir(x) if not k.startswith("_")}


def row_email(x):
    d = as_dict(x)
    return d.get("email") if d else None
