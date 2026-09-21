"""Trust boundary: `invoice_id` comes from the client and can be any number;
`requester_id` is the authenticated caller. Ownership -- not merely being logged
in -- decides what is returned, so the ownership test lives in the WHERE clause.
"""

_COLUMNS = ("id", "owner_id", "amount_cents", "memo")


def get_invoice(conn, requester_id, invoice_id):
    if requester_id is None or invoice_id is None:
        return None
    if isinstance(requester_id, bool) or isinstance(invoice_id, bool):
        return None
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo "
        "FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, requester_id),
    ).fetchone()
    # Someone else's invoice and a non-existent invoice are indistinguishable
    # to the caller: both are None, so this cannot be used to enumerate ids.
    if row is None:
        return None
    return dict(zip(_COLUMNS, tuple(row)))
