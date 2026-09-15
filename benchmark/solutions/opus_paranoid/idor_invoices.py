def get_invoice(conn, requester_id, invoice_id):
    """Return the requester's own invoice as a dict, or None.

    Trust boundary: ``invoice_id`` is a client-supplied id chosen by the
    user opening their dashboard, so it is fully attacker-controlled. A
    logged-in user must only ever read invoices they own. Ownership is
    therefore enforced in the WHERE clause (not merely "is logged in"):
    the caller's id is bound alongside the invoice id. An invoice that
    belongs to someone else is indistinguishable from one that does not
    exist -- both return None -- so we neither serve nor confirm the
    existence of another user's record.

    Both values are passed as bound parameters, never string-formatted,
    so a crafted invoice_id cannot alter the query.
    """
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
