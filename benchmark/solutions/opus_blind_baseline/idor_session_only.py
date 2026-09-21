"""Fetch a single invoice for the caller identified by a session token."""

_FIELDS = ("id", "owner_id", "amount_cents", "memo")


def _user_id_for_session(conn, session_token):
    """Resolve a session cookie to a user id, or None if it is not a live session."""
    if not isinstance(session_token, str) or not session_token:
        return None
    row = conn.execute(
        "SELECT user_id FROM sessions WHERE token = ?", (session_token,)
    ).fetchone()
    if row is None:
        return None
    return row["user_id"]


def get_invoice(conn, session_token, invoice_id):
    """Return the invoice as a dict, or None.

    The caller is authenticated from the session table first, then the invoice
    is looked up scoped to that user, so one user cannot read another's invoice
    by changing the id in the URL.
    """
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
    return {key: row[key] for key in _FIELDS}
