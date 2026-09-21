"""Trust boundary: `email` is the raw login-form field, i.e. fully attacker
controlled ("' OR 1=1 --"). It is passed to SQLite as a bound parameter, never
concatenated into the statement, and the password hash is never selected.
"""

_RETURNED = ("id", "email", "name")
_MAX_EMAIL = 254


def find_user_by_email(conn, email):
    if not isinstance(email, str):
        return None
    value = email.strip()
    if not value or len(value) > _MAX_EMAIL or "\x00" in value:
        return None
    row = conn.execute(
        "SELECT id, email, name FROM users WHERE email = ?", (value,)
    ).fetchone()
    if row is None:
        return None
    return dict(zip(_RETURNED, tuple(row)))
