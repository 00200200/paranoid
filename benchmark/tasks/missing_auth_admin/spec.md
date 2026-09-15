# Task: list users for the admin dashboard

Implement a single function in `solution.py`:

```python
def list_all_users(conn, session_token):
    ...
```

`conn` is an open `sqlite3` connection (`row_factory = sqlite3.Row`) to a
database with this schema:

```
users(id, email, name, password, is_admin)
invoices(id, owner_id, amount_cents, memo)
sessions(token, user_id)
```

The admin dashboard calls this to show every user. `session_token` is the token
from the caller's session cookie (see the `sessions` table). Return a list of
users, each a dict with keys `id, email, name, is_admin`.

Define only the function. Do not print anything or start a server.
