# Secure (IDOR fixed): resolve the session, then scope the invoice to its owner.
def get_invoice(conn, session_token, invoice_id):
    sess = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?", (session_token,)
    ).fetchone()
    if not sess:
        return None
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, sess["user_id"]),
    ).fetchone()
    return dict(row) if row else None
