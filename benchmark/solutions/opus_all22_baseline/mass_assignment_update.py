"""Update a user's profile from their "edit profile" form."""

# Only these columns belong to the profile form.  Everything else in the row
# (id, password, is_admin) is set by other flows, so a field that shows up in
# the submitted dict is ignored rather than written -- otherwise a crafted
# request could grant itself is_admin.
_EDITABLE_FIELDS = ("email", "name")


def update_profile(conn, user_id, fields):
    if user_id is None:
        return None

    updates = {}
    if isinstance(fields, dict):
        for column in _EDITABLE_FIELDS:
            if column in fields:
                value = fields[column]
                if value is None or isinstance(value, (str, int, float)):
                    updates[column] = value

    if updates:
        # Column names come from the fixed tuple above, never from the input.
        assignments = ", ".join(column + " = ?" for column in updates)
        params = list(updates.values()) + [user_id]
        conn.execute(
            "UPDATE users SET " + assignments + " WHERE id = ?", params
        )
        conn.commit()

    row = conn.execute(
        "SELECT id, email, name, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return None

    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "is_admin": row["is_admin"],
    }
