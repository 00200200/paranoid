def list_all_users(conn, session_token):
    row = conn.execute(
        "SELECT u.is_admin AS is_admin FROM sessions s "
        "JOIN users u ON u.id = s.user_id "
        "WHERE s.token = ?",
        (session_token,),
    ).fetchone()
    if row is None or not row["is_admin"]:
        return []
    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users"
    ).fetchall()
    return [
        {
            "id": r["id"],
            "email": r["email"],
            "name": r["name"],
            "is_admin": r["is_admin"],
        }
        for r in rows
    ]
