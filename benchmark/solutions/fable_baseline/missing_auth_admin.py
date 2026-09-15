def list_all_users(conn, session_token):
    caller = conn.execute(
        "SELECT u.is_admin FROM sessions s "
        "JOIN users u ON u.id = s.user_id "
        "WHERE s.token = ?",
        (session_token,),
    ).fetchone()
    if caller is None or not caller["is_admin"]:
        raise PermissionError("admin privileges required")
    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users ORDER BY id"
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
