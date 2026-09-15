# Deliberately vulnerable (IDOR after auth): authenticates, then fetches by id only.
def get_invoice(conn, session_token, invoice_id):
    sess = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?", (session_token,)
    ).fetchone()
    if not sess:
        return None
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    return dict(row) if row else None
