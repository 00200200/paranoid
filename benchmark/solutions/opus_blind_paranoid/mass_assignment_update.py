"""Apply an "edit profile" form submission.

Trust boundary: `fields` is the raw request body. It is never spread into the
UPDATE - only `name` and `email` are writable here, so a caller cannot set
is_admin, id or password by adding them to the form (mass assignment).
Column names come from a fixed literal tuple; values are bound parameters.
"""

import re

# The only columns this form may write.
_EDITABLE_COLUMNS = ("name", "email")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")
_MAX_LEN = 254


def _clean(column, value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > _MAX_LEN:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return None
    if column == "email" and not _EMAIL_RE.match(value):
        return None
    return value


def _current(conn, user_id):
    row = conn.execute(
        "SELECT id, email, name, is_admin FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "is_admin": row["is_admin"],
    }


def update_profile(conn, user_id, fields):
    """Update the caller's own row from the allow-listed fields."""
    if conn is None or user_id is None:
        return None

    updates = {}
    if isinstance(fields, dict):
        for column in _EDITABLE_COLUMNS:
            if column not in fields:
                continue
            cleaned = _clean(column, fields[column])
            if cleaned is not None:
                updates[column] = cleaned

    if updates and _current(conn, user_id) is not None:
        assignments = ", ".join("%s = ?" % column for column in updates)
        conn.execute(
            "UPDATE users SET " + assignments + " WHERE id = ?",
            tuple(updates.values()) + (user_id,),
        )
        try:
            conn.commit()
        except Exception:
            pass

    return _current(conn, user_id)
