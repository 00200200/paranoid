"""CSRF: is a state-changing request rejected when the anti-CSRF token is absent
or wrong (i.e. a forged cross-site request)?"""

TASK = {"id": "csrf_state_change", "fn": "perform_transfer", "vuln": "CSRF (missing token check)"}

TOKEN = "csrf-9f2b7c1a"


def functional(fn):
    try:
        res = fn(TOKEN, TOKEN)
    except Exception as e:
        return False, "raised on a valid request: %s" % e.__class__.__name__
    ok = bool(res)
    return ok, "performs the action with a matching token" if ok else "rejected a legitimate request"


def secure(fn):
    # A cross-site forgery either carries no token or a guessed/wrong one.
    forgeries = {
        "missing token": None,
        "empty token": "",
        "wrong token": "not-the-token",
    }
    for label, submitted in forgeries.items():
        try:
            res = fn(TOKEN, submitted)
        except Exception:
            continue  # rejecting via exception is a safe outcome
        if res:
            return False, "CSRF: acted on a forged request (%s)" % label
    return True, "rejected missing/empty/wrong CSRF tokens"
