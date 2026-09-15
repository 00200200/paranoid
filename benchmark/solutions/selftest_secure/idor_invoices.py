# Secure reference (IDOR fixed): ownership is part of the query.
def get_invoice(conn, requester_id, invoice_id):
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, requester_id),
    ).fetchone()
    return dict(row) if row else None
