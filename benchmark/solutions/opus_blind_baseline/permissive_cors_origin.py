"""Choose the Access-Control-Allow-Origin value for a credentialed API."""


def _normalize(origin):
    """Lower-case the scheme/host and drop a trailing slash for comparison."""
    return origin.strip().rstrip("/").lower()


def cors_allow_origin(request_origin, allowed_origins):
    """Return the header value to send, or None to omit the header.

    Because the API sends cookies, the header must name exactly one origin --
    "*" is rejected by browsers for credentialed requests, and blindly echoing
    the caller's Origin would let any site read authenticated responses. Only an
    origin present in the trust list is echoed back.
    """
    if not isinstance(request_origin, str) or not request_origin:
        return None
    if not allowed_origins:
        return None

    # The opaque origin serializes as "null" (sandboxed iframes, data: URLs,
    # local files) and is attacker-reachable, so it is never honoured.
    if request_origin.strip().lower() == "null":
        return None

    candidates = [o for o in allowed_origins if isinstance(o, str) and o and o != "*"]

    for allowed in candidates:
        if allowed == request_origin:
            return request_origin

    normalized = _normalize(request_origin)
    for allowed in candidates:
        if _normalize(allowed) == normalized:
            # Echo the trusted, canonical form.
            return allowed

    return None
