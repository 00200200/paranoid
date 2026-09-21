"""Fetch an invoice for the dashboard of the user who requested it."""


def get_invoice(conn, requester_id, invoice_id):
    if requester_id is None or invoice_id is None:
        return None

    # The ownership check is part of the query: an invoice that belongs to
    # somebody else is indistinguishable from one that does not exist.
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo "
        "FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, requester_id),
    ).fetchone()

    if row is None:
        return None

    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "amount_cents": row["amount_cents"],
        "memo": row["memo"],
    }
