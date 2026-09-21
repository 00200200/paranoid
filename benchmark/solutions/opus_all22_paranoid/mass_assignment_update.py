"""Trust boundary: `fields` is the raw edit-profile form body. The caller can add
any key they like (is_admin, id, password), so only an explicit allow-list of
columns is ever written, and the column names come from that constant -- never
from the request -- while the values go in as bound parameters.
"""

_EDITABLE_COLUMNS = ("email", "name")
_RETURNED = ("id", "email", "name", "is_admin")
_MAX_EMAIL = 254
_MAX_NAME = 100


def _clean_email(value):
    if not isinstance(value, str):
        return None
    email = value.strip()
    if not email or len(email) > _MAX_EMAIL or "\x00" in email:
        return None
    if any(ch.isspace() for ch in email):
        return None
    if email.count("@") != 1:
        return None
    local, _, domain = email.partition("@")
    if not local or not domain:
        return None
    return email


def _clean_name(value):
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > _MAX_NAME or "\x00" in name:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return None
    return name


def update_profile(conn, user_id, fields):
    if user_id is None or isinstance(user_id, bool):
        return None

    updates = {}
    if isinstance(fields, dict):
        for column in _EDITABLE_COLUMNS:  # iterate the allow-list, not the body
            if column not in fields:
                continue
            cleaned = (
                _clean_email(fields[column])
                if column == "email"
                else _clean_name(fields[column])
            )
            if cleaned is not None:
                updates[column] = cleaned

    if updates:
        assignments = ", ".join(column + " = ?" for column in updates)
        conn.execute(
            "UPDATE users SET " + assignments + " WHERE id = ?",
            tuple(updates.values()) + (user_id,),
        )
        try:
            conn.commit()
        except Exception:
            pass

    row = conn.execute(
        "SELECT id, email, name, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return None
    # password is never selected, so it can never be returned by accident.
    return dict(zip(_RETURNED, tuple(row)))
