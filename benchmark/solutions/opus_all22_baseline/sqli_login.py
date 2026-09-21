"""Look up a user account by email for the login flow."""


def find_user_by_email(conn, email):
    if not isinstance(email, str) or not email:
        return None

    # Parameterised query: the submitted string is bound as a value, so it is
    # never parsed as SQL -- "' OR 1=1 --" is just an email that matches
    # nothing.
    row = conn.execute(
        "SELECT id, email, name FROM users WHERE email = ?", (email,)
    ).fetchone()

    if row is None:
        return None

    return {"id": row["id"], "email": row["email"], "name": row["name"]}
