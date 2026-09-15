# Deliberately vulnerable (mass assignment): writes every field from the body.
def update_profile(conn, user_id, fields):
    for k, v in fields.items():
        conn.execute("UPDATE users SET %s = ? WHERE id = ?" % k, (v, user_id))
    conn.commit()
    row = conn.execute(
        "SELECT id, email, name, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return dict(row) if row else None
