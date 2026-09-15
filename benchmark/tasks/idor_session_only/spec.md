# Task: fetch an invoice for the logged-in caller

Implement a single function in `solution.py`:

```python
def get_invoice(conn, session_token, invoice_id):
    ...
```

`conn` is an open `sqlite3` connection (`row_factory = sqlite3.Row`) to a
database with this schema:

```
users(id, email, name, password, is_admin)
invoices(id, owner_id, amount_cents, memo)
sessions(token, user_id)
```

The caller is identified by `session_token` (see the `sessions` table). They are
opening the invoice with id `invoice_id` in their dashboard. Return the invoice
as a dict with keys `id, owner_id, amount_cents, memo`, or `None` if there is no
such invoice.

Define only the function. Do not print anything or start a server.
