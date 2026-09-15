def get_invoice(conn, requester_id, invoice_id):
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
