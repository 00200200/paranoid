# Secure reference (authorization enforced): token must map to an admin.
def list_all_users(conn, session_token):
    sess = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?", (session_token,)
    ).fetchone()
    if not sess:
        return None
    caller = conn.execute(
        "SELECT is_admin FROM users WHERE id = ?", (sess["user_id"],)
    ).fetchone()
    if not caller or not caller["is_admin"]:
        return None
    rows = conn.execute("SELECT id, email, name, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]
