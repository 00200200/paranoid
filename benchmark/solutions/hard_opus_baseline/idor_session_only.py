def get_invoice(conn, session_token, invoice_id):
    session = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?",
        (session_token,),
    ).fetchone()
    if session is None:
        return None
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo FROM invoices "
        "WHERE id = ? AND owner_id = ?",
        (invoice_id, session["user_id"]),
    ).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "amount_cents": row["amount_cents"],
        "memo": row["memo"],
    }
