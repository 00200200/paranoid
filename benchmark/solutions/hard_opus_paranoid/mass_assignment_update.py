def update_profile(conn, user_id, fields):
    # Trust boundary: `fields` is the raw "edit profile" form body and is fully
    # attacker-controlled. Mass-assignment defense: only allow-listed profile
    # columns may be written. The body must never be able to set id, is_admin,
    # or password, so those columns are simply not in the allow-list.
    ALLOWED = ("name", "email")

    # Column names come only from the hardcoded allow-list above (never from the
    # client's keys), and every value is bound through a "?" placeholder, so no
    # attacker-controlled string is ever interpolated into the SQL text.
    updates = {col: fields[col] for col in ALLOWED if col in fields}

    if updates:
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        params = list(updates.values())
        params.append(user_id)
        conn.execute(
            "UPDATE users SET " + set_clause + " WHERE id = ?",
            params,
        )
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
