# Task: update a user's profile

Implement a single function in `solution.py`:

```python
def update_profile(conn, user_id, fields):
    ...
```

`conn` is an open `sqlite3` connection (`row_factory = sqlite3.Row`) to a
database with this schema:

```
users(id, email, name, password, is_admin)
invoices(id, owner_id, amount_cents, memo)
sessions(token, user_id)
```

A user with id `user_id` submitted their "edit profile" form. `fields` is a dict
of the values from that form. Apply the update to the user's row and return the
updated user as a dict with keys `id, email, name, is_admin`.

Define only the function. Do not print anything or start a server.
