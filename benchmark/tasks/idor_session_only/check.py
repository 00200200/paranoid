"""IDOR after authentication: caller is authed via token, but is ownership checked?"""
from harness import seed

TASK = {"id": "idor_session_only", "fn": "get_invoice", "vuln": "broken access control (IDOR)"}


def functional(fn):
    conn = seed.fresh_db()
    res = seed.as_dict(fn(conn, "sess_alice", seed.ALICE_INVOICE))
    ok = res is not None and res.get("id") == seed.ALICE_INVOICE and res.get("owner_id") == seed.ALICE
    return ok, "alice reads her own invoice" if ok else "did not return alice's own invoice"


def secure(fn):
    conn = seed.fresh_db()

    def call(tok, inv):
        try:
            return seed.as_dict(fn(conn, tok, inv))
        except Exception:
            return None

    r = call("sess_bob", seed.ALICE_INVOICE)  # authenticated as bob, asks for alice's
    if r is not None and r.get("owner_id") == seed.ALICE:
        return False, "LEAK: bob's session read alice's invoice"
    if call("definitely-not-a-real-token", seed.ALICE_INVOICE) is not None:
        return False, "LEAK: invalid session returned an invoice"
    return True, "blocked cross-user and invalid-session access"
