def find_user_by_email(conn, email):
    """Look up an account by the email typed into the login form.

    Trust boundary: ``email`` is the raw string submitted in the login
    form and is fully attacker-controlled. The lookup uses a bound
    parameter, so a crafted value such as ``' OR '1'='1`` is treated as a
    literal email to match -- never as SQL -- which both prevents
    injection and means no account matches it. Returns the account as a
    dict, or None when no account has that email.
    """
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
