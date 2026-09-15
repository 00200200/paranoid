def list_all_users(conn, session_token):
    # Trust boundary: session_token is a raw cookie value (untrusted; may be
    # missing, blank, forged, or belong to a non-admin). The caller's identity
    # and role are resolved from server-side state only (sessions -> users);
    # nothing the client sends is believed without that lookup. Deny by default.
    if not isinstance(session_token, str) or not session_token:
        raise PermissionError("admin session required")
    caller = conn.execute(
        "SELECT u.is_admin FROM sessions AS s "
        "JOIN users AS u ON u.id = s.user_id "
        "WHERE s.token = ?",
        (session_token,),
    ).fetchone()
    if caller is None or not caller[0]:
        raise PermissionError("admin session required")
    # Explicit column list: the password column is never selected or returned.
    rows = conn.execute(
        "SELECT id, email, name, is_admin FROM users ORDER BY id"
    ).fetchall()
    return [
        {"id": r[0], "email": r[1], "name": r[2], "is_admin": r[3]}
        for r in rows
    ]
