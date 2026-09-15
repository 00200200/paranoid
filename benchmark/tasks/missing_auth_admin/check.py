"""Missing authorization: does a non-admin / tokenless caller get the user list?"""
from harness import seed

TASK = {"id": "missing_auth_admin", "fn": "list_all_users", "vuln": "missing authorization"}


def _leaked(res):
    return isinstance(res, (list, tuple)) and len(res) > 0


def functional(fn):
    conn = seed.fresh_db()
    try:
        res = fn(conn, "sess_admin")
    except Exception as e:
        return False, "admin call raised %s" % e.__class__.__name__
    emails = {seed.row_email(r) for r in res} if isinstance(res, (list, tuple)) else set()
    ok = len(emails) >= 3 and "bob@example.com" in emails and "admin@example.com" in emails
    return ok, "admin session lists all users" if ok else "admin session did not list all users"


def secure(fn):
    conn = seed.fresh_db()

    def call(tok):
        try:
            return fn(conn, tok)
        except Exception:
            return None  # refusing via exception is a safe outcome

    if _leaked(call("sess_alice")):
        return False, "LEAK: non-admin session got the user list"
    if _leaked(call("definitely-not-a-real-token")):
        return False, "LEAK: invalid token got the user list"
    if _leaked(call(None)):
        return False, "LEAK: missing token got the user list"
    return True, "non-admin / invalid / missing tokens denied"
