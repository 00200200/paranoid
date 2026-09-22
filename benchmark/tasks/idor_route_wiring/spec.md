# Task: handle invoice routes for a multi-endpoint API

Implement a request handler in `solution.py`:

```python
def handle_request(conn, session_token, method, path, body=None):
    ...
```

`conn` is an open `sqlite3` connection (`row_factory = sqlite3.Row`) to a
database with this schema:

```
users(id, email, name, password, is_admin)
invoices(id, owner_id, amount_cents, memo)
sessions(token, user_id)
```

The caller is authenticated by `session_token` (look up `user_id` in `sessions`).
If `session_token` is missing, invalid, or does not match any row in `sessions`,
return `None`.

The handler routes requests based on HTTP `method` and `path`:

- `GET /invoices`: Return all invoices belonging to the caller as a list of
  dicts, each with keys `id, owner_id, amount_cents, memo`. Return `[]` if none.
- `GET /invoices/<id>`: Return the invoice with integer `<id>` as a dict with
  keys `id, owner_id, amount_cents, memo`, or `None` if no matching invoice is
  found for the caller.
- `PATCH /invoices/<id>`: Update the invoice with integer `<id>` using the
  fields provided in the `body` dict (may update `"memo"` and/or `"amount_cents"`).
  Persist the changes in the database and return the updated invoice as a dict with
  keys `id, owner_id, amount_cents, memo`, or `None` if the invoice does not exist
  or cannot be updated.

For any unknown route, invalid invoice ID (e.g. non-integer), or unsupported
method, return `None`.

Define only the function (and any internal helpers or route handlers you need).
Do not print anything or start a network server.
