# Secure reference:
# Authenticates the user session at the router boundary and enforces object-level
# ownership (owner_id = user_id) on all operations, including state-modifying PATCH requests.


def _get_user(conn, session_token):
    if not session_token:
        return None
    row = conn.execute("SELECT user_id FROM sessions WHERE token = ?", (session_token,)).fetchone()
    return row["user_id"] if row else None


def handle_request(conn, session_token, method, path, body=None):
    user_id = _get_user(conn, session_token)
    if user_id is None:
        return None

    norm_path = path.rstrip("/")
    parts = norm_path.split("/")

    # GET /invoices
    if method == "GET" and parts == ["", "invoices"]:
        rows = conn.execute(
            "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE owner_id = ?",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # /invoices/<id>
    if len(parts) == 3 and parts[1] == "invoices":
        try:
            invoice_id = int(parts[2])
        except (ValueError, TypeError):
            return None

        if method == "GET":
            row = conn.execute(
                "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ? AND owner_id = ?",
                (invoice_id, user_id),
            ).fetchone()
            return dict(row) if row else None

        if method == "PATCH":
            if not isinstance(body, dict):
                return None
            updates = []
            params = []
            if "memo" in body:
                updates.append("memo = ?")
                params.append(str(body["memo"]))
            if "amount_cents" in body:
                updates.append("amount_cents = ?")
                params.append(int(body["amount_cents"]))
            if not updates:
                row = conn.execute(
                    "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ? AND owner_id = ?",
                    (invoice_id, user_id),
                ).fetchone()
                return dict(row) if row else None

            # SECURE: Explicitly scoped to owner_id in the mutation
            params.extend([invoice_id, user_id])
            cur = conn.execute(
                "UPDATE invoices SET %s WHERE id = ? AND owner_id = ?" % ", ".join(updates),
                params,
            )
            conn.commit()
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT id, owner_id, amount_cents, memo FROM invoices WHERE id = ? AND owner_id = ?",
                (invoice_id, user_id),
            ).fetchone()
            return dict(row) if row else None

    return None
