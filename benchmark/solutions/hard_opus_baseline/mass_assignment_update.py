def update_profile(conn, user_id, fields):
    editable = ("name", "email")
    updates = {col: fields[col] for col in editable if col in fields}
    if updates:
        set_clause = ", ".join(col + " = ?" for col in updates)
        params = list(updates.values())
        params.append(user_id)
        conn.execute("UPDATE users SET " + set_clause + " WHERE id = ?", params)
        conn.commit()
    row = conn.execute(
        "SELECT id, email, name, is_admin FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "is_admin": row["is_admin"],
    }
