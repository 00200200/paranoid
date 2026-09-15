def get_invoice(conn, session_token, invoice_id):
    # Trust boundary: both `session_token` and `invoice_id` are client-supplied.
    # 1) Resolve the token against server-side session state to learn the
    #    caller's real user id; a missing/blind token means no caller -> None.
    # 2) IDOR defense: only return the invoice if it belongs to that caller.
    #    The owner check lives in the WHERE clause so another user's invoice is
    #    indistinguishable from a non-existent one (both -> None).
    if not session_token:
        return None

    session = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?",
        (session_token,),
    ).fetchone()
    if session is None:
        return None

    user_id = session["user_id"]

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
