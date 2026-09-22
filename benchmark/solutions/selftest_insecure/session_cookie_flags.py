# Deliberately vulnerable reference (missing cookie flags): issues a bare
# name=value session cookie with no HttpOnly / Secure / SameSite, so XSS,
# cleartext, and cross-site requests can all touch it.
def issue_session_cookie(name, value):
    return {"name": name, "value": value}
