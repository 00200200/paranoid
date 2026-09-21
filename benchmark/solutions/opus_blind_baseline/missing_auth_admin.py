"""List every user for the admin dashboard."""

_FIELDS = ("id", "email", "name", "is_admin")


def list_all_users(conn, session_token):
    """Return all users, but only for a caller whose session belongs to an admin.

    An unauthenticated or non-admin caller gets an empty list; the endpoint must
    not rely on the UI hiding the link. Password hashes are never selected.
    """
    if not isinstance(session_token, str) or not session_token:
        return []

    caller = conn.execute(
        "SELECT users.is_admin AS is_admin "
        "FROM sessions JOIN users ON users.id = sessions.user_id "
        "WHERE sessions.token = ?",
        (session_token,),
    ).fetchone()

    if caller is None or not caller["is_admin"]:
        return []

    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users ORDER BY id"
    ).fetchall()
    return [{key: row[key] for key in _FIELDS} for row in rows]
