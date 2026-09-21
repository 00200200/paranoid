"""Fetch an invoice for the caller identified by their session token."""


def get_invoice(conn, session_token, invoice_id):
    if not isinstance(session_token, str) or not session_token:
        return None
    if invoice_id is None:
        return None

    # Identify the caller from the session; never trust a caller-supplied id.
    session = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?", (session_token,)
    ).fetchone()
    if session is None:
        return None

    user_id = session["user_id"]
    if user_id is None:
        return None

    # Scope the lookup to that user, so another account's invoice simply is
    # not found rather than being returned.
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo "
        "FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, user_id),
    ).fetchone()
    if row is None:
        return None

    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "amount_cents": row["amount_cents"],
        "memo": row["memo"],
    }
