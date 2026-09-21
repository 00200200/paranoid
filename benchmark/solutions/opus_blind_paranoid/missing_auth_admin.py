"""Admin-only listing of every user.

Trust boundary: `session_token` is a cookie value the caller controls. The
token is resolved server-side and the is_admin flag is checked before any
row is returned - a valid session for a normal user is not enough. Password
hashes are never selected into the response.
"""


def _is_true(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "t", "y"}
    return False


def list_all_users(conn, session_token):
    """Return every user if the caller is an admin, else an empty list."""
    if conn is None or not isinstance(session_token, str) or not session_token:
        return []

    caller = conn.execute(
        "SELECT u.id AS id, u.is_admin AS is_admin "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token = ?",
        (session_token,),
    ).fetchone()

    if caller is None or not _is_true(caller["is_admin"]):
        return []

    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users ORDER BY id"
    ).fetchall()
    return [
        {
            "id": row["id"],
            "email": row["email"],
            "name": row["name"],
            "is_admin": row["is_admin"],
        }
        for row in rows
    ]
