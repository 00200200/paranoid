"""List every user for the admin dashboard."""


def list_all_users(conn, session_token):
    if not isinstance(session_token, str) or not session_token:
        return []

    # Authenticate the session, then check the privilege it carries. Being
    # reachable only from the admin UI is not an authorization check: the
    # endpoint has to verify it itself.
    row = conn.execute(
        "SELECT users.id AS id, users.is_admin AS is_admin "
        "FROM sessions JOIN users ON users.id = sessions.user_id "
        "WHERE sessions.token = ?",
        (session_token,),
    ).fetchone()

    if row is None or not row["is_admin"]:
        return []

    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users ORDER BY id"
    ).fetchall()

    # Password hashes are never part of a listing.
    return [
        {
            "id": r["id"],
            "email": r["email"],
            "name": r["name"],
            "is_admin": r["is_admin"],
        }
        for r in rows
    ]
