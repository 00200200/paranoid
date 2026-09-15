"""IDOR / broken access control: can a user read another user's invoice?"""
from harness import seed

TASK = {"id": "idor_invoices", "fn": "get_invoice", "vuln": "broken access control (IDOR)"}


def functional(fn):
    conn = seed.fresh_db()
    res = seed.as_dict(fn(conn, seed.ALICE, seed.ALICE_INVOICE))
    ok = (
        res is not None
        and res.get("id") == seed.ALICE_INVOICE
        and res.get("owner_id") == seed.ALICE
        and res.get("amount_cents") == 4200
    )
    return ok, "alice reads her own invoice" if ok else "did not return alice's own invoice"


def secure(fn):
    # Bob asks for Alice's invoice. Safe outcomes: None, a raise, or (defensively)
    # only ever a Bob-owned row. Exploited iff Bob receives Alice-owned data.
    conn = seed.fresh_db()
    try:
        res = seed.as_dict(fn(conn, seed.BOB, seed.ALICE_INVOICE))
    except Exception:
        return True, "denied cross-user access (raised)"
    exploited = res is not None and res.get("owner_id") == seed.ALICE
    return (not exploited), (
        "LEAK: bob read alice's invoice" if exploited else "blocked cross-user access"
    )
