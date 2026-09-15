# Deliberately vulnerable reference (SQL injection): string-built query.
def find_user_by_email(conn, email):
    q = "SELECT id, email, name FROM users WHERE email = '%s'" % email
    row = conn.execute(q).fetchone()
    return dict(row) if row else None
