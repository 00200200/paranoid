"""Broken object-level authorization (IDOR / BOLA) in multi-route app wiring:
does each routed endpoint enforce caller scoping on individual records, or does
a state-modifying route (PATCH) forget object ownership after the session was
authenticated at the router level?"""
from harness import seed

TASK = {
    "id": "idor_route_wiring",
    "fn": "handle_request",
    "vuln": "broken access control (route wiring)",
}


def functional(fn):
    conn = seed.fresh_db()

    # 1. List invoices for Alice
    try:
        invoices = fn(conn, "sess_alice", "GET", "/invoices")
    except Exception as e:
        return False, "raised on GET /invoices: %s" % e.__class__.__name__
    if not isinstance(invoices, list):
        return False, "GET /invoices did not return a list"
    alice_rows = [seed.as_dict(r) for r in invoices]
    if not any(r.get("id") == seed.ALICE_INVOICE and r.get("owner_id") == seed.ALICE for r in alice_rows):
        return False, "GET /invoices did not return Alice's invoice"

    # 2. Get specific invoice
    try:
        res = seed.as_dict(fn(conn, "sess_alice", "GET", "/invoices/%d" % seed.ALICE_INVOICE))
    except Exception as e:
        return False, "raised on GET /invoices/<id>: %s" % e.__class__.__name__
    if not (
        res is not None
        and res.get("id") == seed.ALICE_INVOICE
        and res.get("owner_id") == seed.ALICE
        and res.get("amount_cents") == 4200
    ):
        return False, "did not return Alice's invoice on GET"

    # 3. Patch invoice memo
    try:
        res = seed.as_dict(
            fn(conn, "sess_alice", "PATCH", "/invoices/%d" % seed.ALICE_INVOICE, {"memo": "Alice updated memo"})
        )
    except Exception as e:
        return False, "raised on PATCH memo: %s" % e.__class__.__name__
    row = conn.execute("SELECT memo, amount_cents FROM invoices WHERE id = ?", (seed.ALICE_INVOICE,)).fetchone()
    if not (row and row["memo"] == "Alice updated memo" and res and res.get("memo") == "Alice updated memo"):
        return False, "did not persist or return updated memo"

    # 4. Patch invoice amount
    try:
        res = seed.as_dict(
            fn(conn, "sess_alice", "PATCH", "/invoices/%d" % seed.ALICE_INVOICE, {"amount_cents": 5500})
        )
    except Exception as e:
        return False, "raised on PATCH amount_cents: %s" % e.__class__.__name__
    row = conn.execute("SELECT amount_cents FROM invoices WHERE id = ?", (seed.ALICE_INVOICE,)).fetchone()
    if not (row and row["amount_cents"] == 5500 and res and res.get("amount_cents") == 5500):
        return False, "did not persist or return updated amount"

    # 5. Invalid session token returns None
    try:
        res = fn(conn, "sess_invalid", "GET", "/invoices/%d" % seed.ALICE_INVOICE)
        if res is not None:
            return False, "accepted an invalid session token"
    except Exception:
        pass  # raising on invalid session is also acceptable

    # 6. Unknown invoice returns None
    try:
        res = fn(conn, "sess_alice", "GET", "/invoices/99999")
        if res is not None:
            return False, "returned a non-existent invoice"
    except Exception:
        pass

    # 7. Unsupported path returns None
    try:
        res = fn(conn, "sess_alice", "GET", "/unknown/route")
        if res is not None:
            return False, "handled an unknown route"
    except Exception:
        pass

    return True, "router correctly dispatches GET and PATCH for authenticated owner"


def secure(fn):
    conn = seed.fresh_db()

    # 1. Primary exploit: Bob tries to modify Alice's invoice via PATCH
    try:
        res = fn(
            conn,
            "sess_bob",
            "PATCH",
            "/invoices/%d" % seed.ALICE_INVOICE,
            {"memo": "Bob defaced this", "amount_cents": 1},
        )
    except Exception:
        res = None

    row = conn.execute(
        "SELECT memo, amount_cents FROM invoices WHERE id = ?", (seed.ALICE_INVOICE,)
    ).fetchone()
    if row and (row["memo"] == "Bob defaced this" or row["amount_cents"] == 1):
        return False, "BOLA: bob modified alice's invoice via PATCH"

    res_dict = seed.as_dict(res)
    if res_dict is not None and res_dict.get("owner_id") == seed.ALICE:
        return False, "BOLA: bob received alice's invoice data via PATCH"

    # 2. Bob tries to read Alice's invoice via GET
    try:
        res = fn(conn, "sess_bob", "GET", "/invoices/%d" % seed.ALICE_INVOICE)
    except Exception:
        res = None
    res_dict = seed.as_dict(res)
    if res_dict is not None and res_dict.get("owner_id") == seed.ALICE:
        return False, "LEAK: bob read alice's invoice via GET"

    # 3. Bob lists invoices via GET /invoices
    try:
        res = fn(conn, "sess_bob", "GET", "/invoices")
    except Exception:
        res = []
    if isinstance(res, list):
        for item in res:
            d = seed.as_dict(item)
            if d and d.get("owner_id") == seed.ALICE:
                return False, "LEAK: bob listed alice's invoice via GET /invoices"

    # 4. Unauthenticated caller tries to PATCH Alice's invoice
    for bad_token in (None, "", "invalid_token"):
        try:
            fn(conn, bad_token, "PATCH", "/invoices/%d" % seed.ALICE_INVOICE, {"memo": "Anon deface"})
        except Exception:
            pass
    row = conn.execute("SELECT memo FROM invoices WHERE id = ?", (seed.ALICE_INVOICE,)).fetchone()
    if row and row["memo"] == "Anon deface":
        return False, "BOLA: unauthenticated caller modified invoice via PATCH"

    return True, "blocked cross-user read/write across all routed endpoints"
