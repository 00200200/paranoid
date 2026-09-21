"""Invoice lookup for a logged-in user's dashboard.

Trust boundary: `invoice_id` is supplied by the client and can be any id,
including another tenant's. Being logged in is not authorisation, so the
query filters on ownership as well as id (prevents IDOR); values are bound
as parameters, never concatenated into SQL.
"""


def get_invoice(conn, requester_id, invoice_id):
    """Return the invoice owned by `requester_id`, or None."""
    if conn is None or requester_id is None or invoice_id is None:
        return None
    row = conn.execute(
        "SELECT id, owner_id, amount_cents, memo "
        "FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, requester_id),
    ).fetchone()
    if row is None:
        # Same answer for "does not exist" and "not yours": no enumeration.
        return None
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "amount_cents": row["amount_cents"],
        "memo": row["memo"],
    }
