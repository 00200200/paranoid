def find_user_by_email(conn, email):
    row = conn.execute(
        "SELECT id, email, name FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
    }
