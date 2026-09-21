"""Apply a user's own "edit profile" form submission."""

# Only these columns may be set from the form. Binding the whole `fields` dict
# to the row would let a user post is_admin=1 (or overwrite id / password) and
# escalate their own privileges.
_EDITABLE_COLUMNS = ("email", "name")

_RETURN_FIELDS = ("id", "email", "name", "is_admin")


def _load_user(conn, user_id):
    row = conn.execute(
        "SELECT id, email, name, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return None
    return {key: row[key] for key in _RETURN_FIELDS}


def update_profile(conn, user_id, fields):
    """Update the user's editable profile columns and return the updated user."""
    if user_id is None:
        return None
    if not isinstance(fields, dict):
        fields = {}

    updates = []
    values = []
    for column in _EDITABLE_COLUMNS:
        if column not in fields:
            continue
        value = fields[column]
        if value is not None and not isinstance(value, str):
            continue
        # The column name comes from the constant tuple above, never from the
        # request, and the value is bound as a parameter.
        updates.append(column + " = ?")
        values.append(value)

    if updates:
        values.append(user_id)
        conn.execute(
            "UPDATE users SET " + ", ".join(updates) + " WHERE id = ?", values
        )
        conn.commit()

    return _load_user(conn, user_id)
