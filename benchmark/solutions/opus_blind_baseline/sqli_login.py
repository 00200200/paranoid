"""Look up an account by email during login."""

_FIELDS = ("id", "email", "name")


def find_user_by_email(conn, email):
    """Return the matching user as a dict, or None.

    `email` is raw form input, so it is bound as a query parameter. Building the
    SQL by string formatting would let "' OR '1'='1" log in as the first user.
    """
    if not isinstance(email, str) or not email:
        return None

    row = conn.execute(
        "SELECT id, email, name FROM users WHERE email = ? LIMIT 1", (email,)
    ).fetchone()

    if row is None:
        return None
    return {key: row[key] for key in _FIELDS}
