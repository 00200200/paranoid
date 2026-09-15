# Secure (mass assignment fixed): allow-list the editable fields.
def update_profile(conn, user_id, fields):
    allowed = {"name", "email"}
    for k, v in fields.items():
        if k in allowed:
            conn.execute("UPDATE users SET %s = ? WHERE id = ?" % k, (v, user_id))
    conn.commit()
    row = conn.execute(
        "SELECT id, email, name, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return dict(row) if row else None
