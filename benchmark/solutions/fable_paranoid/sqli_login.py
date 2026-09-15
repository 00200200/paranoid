def find_user_by_email(conn, email):
    # Trust boundary: email is the raw login-form value (untrusted). It is passed
    # only as a bound parameter -- never interpolated into the SQL text -- so input
    # such as "' OR '1'='1" or "x' UNION SELECT ..." is compared literally as an
    # email string and matches nothing. The password column is never selected.
    if not isinstance(email, str):
        return None
    row = conn.execute(
        "SELECT id, email, name FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    if row is None:
        return None
    user_id, user_email, name = row
    return {"id": user_id, "email": user_email, "name": name}
