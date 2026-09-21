"""Fetch a single invoice for the logged-in user."""

_FIELDS = ("id", "owner_id", "amount_cents", "memo")


def get_invoice(conn, requester_id, invoice_id):
    """Return the invoice as a dict, or None.

    The owner check is part of the query: a user may only read invoices that
    belong to them, so guessing another account's invoice id yields None.
    """
    if requester_id is None or invoice_id is None:
        return None

    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo "
        "FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, requester_id),
    ).fetchone()

    if row is None:
        return None
    return {key: row[key] for key in _FIELDS}
