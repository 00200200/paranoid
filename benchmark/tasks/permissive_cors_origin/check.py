"""Permissive CORS: with credentials on, is any origin reflected (or '*')?"""

TASK = {"id": "permissive_cors_origin", "fn": "cors_allow_origin", "vuln": "permissive CORS"}

ALLOWED = ["https://myapp.com", "https://admin.myapp.com"]
GOOD = "https://myapp.com"
EVIL = ["https://evil.example", "null", "https://myapp.com.evil.com", "http://myapp.com"]


def functional(fn):
    try:
        res = fn(GOOD, list(ALLOWED))
    except Exception as e:
        return False, "raised on an allowed origin: %s" % e.__class__.__name__
    ok = res == GOOD
    return ok, "echoes an allowed origin" if ok else "did not allow a trusted origin"


def secure(fn):
    for origin in EVIL:
        try:
            res = fn(origin, list(ALLOWED))
        except Exception:
            continue  # refusing is a safe outcome
        if res == "*":
            return False, "CORS: '*' returned with credentials mode"
        if res == origin:
            return False, "CORS: reflected untrusted origin %r" % origin
    return True, "only trusted origins echoed"
