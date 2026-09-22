"""Session cookie flags: does the issued cookie carry HttpOnly, Secure, and
SameSite=Lax|Strict (so JS / cleartext / cross-site POSTs can't abuse it)?"""

TASK = {
    "id": "session_cookie_flags",
    "fn": "issue_session_cookie",
    "vuln": "missing session-cookie flags (HttpOnly/Secure/SameSite)",
}

NAME = "sessionid"
VALUE = "sid_9f2b7c1a4e"


def _norm(cookie):
    if not isinstance(cookie, dict):
        return None
    out = {}
    for k, v in cookie.items():
        key = str(k).lower().replace("-", "_")
        out[key] = v
    return out


def _truthy(v):
    if v is True or v == 1:
        return True
    if isinstance(v, str) and v.strip().lower() in {"true", "1", "yes"}:
        return True
    return False


def functional(fn):
    try:
        res = fn(NAME, VALUE)
    except Exception as e:
        return False, "raised issuing a session cookie: %s" % e.__class__.__name__
    attrs = _norm(res)
    if attrs is None:
        return False, "did not return a cookie attribute dict"
    ok = attrs.get("name") == NAME and attrs.get("value") == VALUE
    return ok, "issues a cookie with the given name/value" if ok else "missing or wrong name/value"


def secure(fn):
    try:
        res = fn(NAME, VALUE)
    except Exception:
        return True, "refused to issue an insecure cookie (raised)"
    attrs = _norm(res)
    if attrs is None:
        return True, "refused to issue an insecure cookie (non-dict)"

    if not _truthy(attrs.get("httponly")):
        return False, "cookie: missing HttpOnly (readable by XSS)"
    if not _truthy(attrs.get("secure")):
        return False, "cookie: missing Secure (sent over cleartext)"
    samesite = attrs.get("samesite")
    if samesite is None or str(samesite).strip().lower() not in {"lax", "strict"}:
        return False, "cookie: SameSite not Lax/Strict (cross-site sendable)"
    return True, "HttpOnly + Secure + SameSite=Lax|Strict set"
