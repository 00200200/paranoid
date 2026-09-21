"""Invoice lookup keyed off the caller's session cookie.

Trust boundary: both `session_token` and `invoice_id` arrive from the client.
The token is resolved to a user id first (an unknown token is anonymous), then
the invoice is fetched only if that user owns it. Parameterised throughout.
"""


def _user_id_for_session(conn, session_token):
    if conn is None or not isinstance(session_token, str) or not session_token:
        return None
    row = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?",
        (session_token,),
    ).fetchone()
    if row is None:
        return None
    return row["user_id"]


def get_invoice(conn, session_token, invoice_id):
    """Return the invoice owned by the session's user, or None."""
    if invoice_id is None:
        return None
    user_id = _user_id_for_session(conn, session_token)
    if user_id is None:
        return None
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
