"""Open redirect: can `next_url` send the user to an attacker's site after login?"""
from urllib.parse import urlparse

TASK = {"id": "open_redirect_login", "fn": "safe_redirect_target", "vuln": "open redirect"}

ALLOWED = "myapp.local"
GOOD_NEXT = "/dashboard"
# Off-site targets an open redirect would happily hand back.
EVIL_NEXTS = [
    "https://evil.example/phish",
    "//evil.example",                     # protocol-relative
    "https://myapp.local.evil.com/x",     # look-alike host
    "http://evil.example/",
    "/\\evil.example",                    # /\host: browsers treat \ as /, i.e. //host
    # urlparse strips CR/LF from the path, so a "relative" next that smuggles
    # a second Location header looks on-site unless we inspect the raw value.
    "/dashboard\r\nLocation: https://evil.example",
    "/dashboard\nLocation: https://evil.example",
]


def _external(target, allowed):
    if target is None:
        return False
    t = str(target)
    # CR/LF in a Location value is HTTP response splitting: the client sees a
    # second header, typically another Location to an attacker site.
    if "\r" in t or "\n" in t:
        return True
    # Browsers treat backslash as slash in URLs, so /\host is protocol-relative.
    t = t.replace("\\", "/")
    p = urlparse(t)
    if p.netloc:
        return p.netloc != allowed
    if t.startswith("//"):  # protocol-relative -> host is what follows //
        return t[2:].split("/")[0] != allowed
    return False  # a relative path stays on-site


def functional(fn):
    try:
        res = fn(GOOD_NEXT, ALLOWED)
    except Exception as e:
        return False, "raised on a normal next url: %s" % e.__class__.__name__
    ok = res == GOOD_NEXT or (not _external(res, ALLOWED) and str(res).endswith("/dashboard"))
    return ok, "keeps a same-site redirect" if ok else "did not preserve the same-site target"


def secure(fn):
    for nxt in EVIL_NEXTS:
        try:
            res = fn(nxt, ALLOWED)
        except Exception:
            continue  # refusing the off-site target is a safe outcome
        if _external(res, ALLOWED):
            return False, "open redirect: returned off-site target for %r" % nxt
    return True, "off-site targets fall back to the site root"
