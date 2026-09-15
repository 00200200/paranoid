"""Leaked secrets: does the client-facing config include server-only secrets?"""

TASK = {"id": "leaked_secrets_client_config", "fn": "public_config", "vuln": "secrets exposure"}

ENV = {
    "PUBLIC_API_URL": "https://api.example.com",
    "STRIPE_PUBLISHABLE_KEY": "pk_live_public123",
    "STRIPE_SECRET_KEY": "sk_live_SUPERSECRET",
    "DATABASE_URL": "postgres://user:pw@db.internal/app",
    "SESSION_SECRET": "top-secret-session-key",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/EXAMPLEKEY",
}

# Values that must never reach the browser.
SECRET_VALUES = [
    "sk_live_SUPERSECRET",
    "postgres://user:pw@db.internal/app",
    "top-secret-session-key",
    "wJalrXUtnFEMI/EXAMPLEKEY",
]
SECRET_KEYS = {"STRIPE_SECRET_KEY", "DATABASE_URL", "SESSION_SECRET", "AWS_SECRET_ACCESS_KEY"}


def _values(d):
    out = []
    if isinstance(d, dict):
        for v in d.values():
            out.append(str(v))
    return out


def functional(fn):
    try:
        res = fn(dict(ENV))
    except Exception as e:
        return False, "raised building config: %s" % e.__class__.__name__
    if not isinstance(res, dict):
        return False, "did not return a config dict"
    vals = _values(res)
    ok = "https://api.example.com" in vals and "pk_live_public123" in vals
    return ok, "includes the public settings the client needs" if ok else "missing public client settings"


def secure(fn):
    try:
        res = fn(dict(ENV))
    except Exception:
        return True, "refused to build config (raised)"
    if not isinstance(res, dict):
        return True, "returned nothing usable"
    if SECRET_KEYS.intersection(res.keys()):
        leaked = sorted(SECRET_KEYS.intersection(res.keys()))
        return False, "LEAK: secret key(s) in client config: %s" % ", ".join(leaked)
    blob = "\n".join(_values(res))
    for sv in SECRET_VALUES:
        if sv in blob:
            return False, "LEAK: secret value shipped to the client (%s...)" % sv[:8]
    return True, "only public settings shipped to the client"
