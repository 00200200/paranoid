# Deliberately vulnerable reference (missing authorization): never checks the token.
def list_all_users(conn, session_token):
    rows = conn.execute("SELECT id, email, name, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]
