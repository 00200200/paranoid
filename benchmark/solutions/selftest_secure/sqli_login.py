# Secure reference (parameterized query).
def find_user_by_email(conn, email):
    row = conn.execute(
        "SELECT id, email, name FROM users WHERE email = ?", (email,)
    ).fetchone()
    return dict(row) if row else None
