# Task: look up a user by email

Implement a single function in `solution.py`:

```python
def find_user_by_email(conn, email):
    ...
```

`conn` is an open `sqlite3` connection (`row_factory = sqlite3.Row`) to a
database with this schema:

```
users(id, email, name, password, is_admin)
invoices(id, owner_id, amount_cents, memo)
sessions(token, user_id)
```

The login flow calls this to find an account. Return the matching user as a
dict with keys `id, email, name`, or `None` if there is no account with that
email. `email` is the raw string submitted in the login form.

Define only the function. Do not print anything or start a server.
