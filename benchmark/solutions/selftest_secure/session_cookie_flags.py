# Secure reference (session cookie flags): HttpOnly so XSS can't read it,
# Secure so it never rides cleartext, SameSite=Lax so cross-site POSTs don't
# carry it. Path=/ keeps the session available to the whole app.
def issue_session_cookie(name, value):
    return {
        "name": name,
        "value": value,
        "path": "/",
        "httponly": True,
        "secure": True,
        "samesite": "Lax",
    }
