"""Choose the Access-Control-Allow-Origin value for a credentialed API."""


def cors_allow_origin(request_origin, allowed_origins):
    if not isinstance(request_origin, str):
        return None

    origin = request_origin.strip()
    if not origin:
        return None

    if not allowed_origins:
        return None

    # Echo the Origin only when it is one we actually trust -- exact match on
    # scheme, host and port. Reflecting whatever arrives (or sending "*", or
    # matching a suffix like "evil-myapp.com") would hand any site the ability
    # to read authenticated responses, since credentials are in play.
    for allowed in allowed_origins:
        if isinstance(allowed, str) and origin == allowed.strip():
            return origin

    # No header at all: the browser blocks the cross-origin read.
    return None
