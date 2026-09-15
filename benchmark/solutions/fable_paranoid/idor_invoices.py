def get_invoice(conn, requester_id, invoice_id):
    # Trust boundary: requester_id comes from the server-side session (trusted);
    # invoice_id comes from the client (untrusted). Ownership is enforced in the
    # WHERE clause, so a caller can never read another user's invoice by guessing
    # or tampering with ids. An ownership miss is indistinguishable from "no such
    # invoice" (None), so ids cannot be enumerated either.
    if requester_id is None:
        return None
    if not isinstance(invoice_id, (int, str)):
        return None
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo "
        "FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, requester_id),
    ).fetchone()
    if row is None:
        return None
    inv_id, owner_id, amount_cents, memo = row
    return {
        "id": inv_id,
        "owner_id": owner_id,
        "amount_cents": amount_cents,
        "memo": memo,
    }
