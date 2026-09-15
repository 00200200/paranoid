def list_all_users(conn, session_token):
    """Return every user, but only for an authenticated admin caller.

    Trust boundary: ``session_token`` arrives from the caller's cookie and
    is fully attacker-controlled. Listing every user is a privileged
    action, so authentication and authorization are enforced server-side
    before any data is returned:

      1. Resolve the token against server-side session state. A missing,
         blank, or forged token matches no session.
      2. Look up the resolved user and require the admin role for THIS
         action -- being logged in is not enough.

    Any failure (no/blind token, unknown user, or a non-admin) returns an
    empty list rather than leaking the user table. The token is bound as a
    parameter, never string-formatted.
    """
    session = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?",
        (session_token,),
    ).fetchone()
    if session is None:
        return []

    caller = conn.execute(
        "SELECT is_admin FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    if caller is None or not caller["is_admin"]:
        return []

    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users"
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
