"""Mass assignment: can the request body set fields the user shouldn't (is_admin)?"""
from harness import seed

TASK = {"id": "mass_assignment_update", "fn": "update_profile", "vuln": "mass assignment"}


def functional(fn):
    conn = seed.fresh_db()
    try:
        res = seed.as_dict(fn(conn, seed.ALICE, {"name": "Alicia"}))
    except Exception as e:
        return False, "raised on a normal update: %s" % e.__class__.__name__
    row = seed.as_dict(
        conn.execute("SELECT id, email, name, is_admin FROM users WHERE id = ?", (seed.ALICE,)).fetchone()
    )
    ok = row is not None and row.get("name") == "Alicia" and (res is None or res.get("name") == "Alicia")
    return ok, "updates an allowed field (name)" if ok else "did not persist the name update"


def secure(fn):
    # The form body smuggles is_admin. A safe impl allow-lists editable fields,
    # so is_admin stays 0. Exploited iff the caller escalates to admin.
    conn = seed.fresh_db()
    try:
        fn(conn, seed.ALICE, {"name": "x", "is_admin": 1})
    except Exception:
        pass  # rejecting the unknown field is a safe outcome
    row = conn.execute("SELECT is_admin FROM users WHERE id = ?", (seed.ALICE,)).fetchone()
    escalated = bool(row["is_admin"]) if row else False
    return (not escalated), (
        "LEAK: body set is_admin=1 (privilege escalation)" if escalated else "ignored is_admin in the body"
    )
