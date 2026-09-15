# Deliberately vulnerable reference (IDOR): ignores requester_id.
def get_invoice(conn, requester_id, invoice_id):
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ?",
        (invoice_id,),
    ).fetchone()
    return dict(row) if row else None
