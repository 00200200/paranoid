"""Look up an account during login.

Trust boundary: `email` is the raw login-form string - the canonical SQL
injection vector ("' OR '1'='1"). It is passed as a bound parameter, never
concatenated, and the password column is never selected, so a lookup cannot
leak the stored hash.
"""

_MAX_EMAIL_LEN = 320


def find_user_by_email(conn, email):
    """Return the matching user (id, email, name), or None."""
    if conn is None or not isinstance(email, str):
        return None
    value = email.strip()
    if not value or len(value) > _MAX_EMAIL_LEN:
        return None

    row = conn.execute(
        "SELECT id, email, name FROM users WHERE email = ?",
        (value,),
    ).fetchone()
    if row is None:
        return None
    return {"id": row["id"], "email": row["email"], "name": row["name"]}
