"""Trust boundary: the caller presents only a session cookie value, which is
attacker-supplied, plus an invoice id that is attacker-chosen. The token must be
resolved to a user server-side, and the invoice must belong to that user.
"""

_COLUMNS = ("id", "owner_id", "amount_cents", "memo")


def _user_id_for_session(conn, session_token):
    if not isinstance(session_token, str) or not session_token:
        return None
    if len(session_token) > 512 or "\x00" in session_token:
        return None
    row = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?", (session_token,)
    ).fetchone()
    if row is None:
        return None
    return tuple(row)[0]


def get_invoice(conn, session_token, invoice_id):
    # No valid session => no data, ever.
    user_id = _user_id_for_session(conn, session_token)
    if user_id is None:
        return None
    if invoice_id is None or isinstance(invoice_id, bool):
        return None
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo "
        "FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, user_id),
    ).fetchone()
    if row is None:
        return None
    return dict(zip(_COLUMNS, tuple(row)))
