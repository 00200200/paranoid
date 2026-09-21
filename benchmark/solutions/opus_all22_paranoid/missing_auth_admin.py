"""Trust boundary: an admin-only listing of every user. The caller supplies only
a session cookie, so the endpoint authenticates it server-side and then checks
the is_admin flag from the database (never from the request). Anyone else gets
an empty list, and password hashes are never selected.
"""

_RETURNED = ("id", "email", "name", "is_admin")


def _admin_user_id(conn, session_token):
    if not isinstance(session_token, str) or not session_token:
        return None
    if len(session_token) > 512 or "\x00" in session_token:
        return None
    row = conn.execute(
        "SELECT u.id, u.is_admin FROM sessions s "
        "JOIN users u ON u.id = s.user_id WHERE s.token = ?",
        (session_token,),
    ).fetchone()
    if row is None:
        return None
    user_id, is_admin = tuple(row)[0], tuple(row)[1]
    # Deny by default: only a truthy is_admin from the users table grants access.
    if not is_admin:
        return None
    return user_id


def list_all_users(conn, session_token):
    if _admin_user_id(conn, session_token) is None:
        return []
    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users ORDER BY id"
    ).fetchall()
    return [dict(zip(_RETURNED, tuple(row))) for row in rows]
