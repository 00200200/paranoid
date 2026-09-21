"""Decide the Access-Control-Allow-Origin value for a credentialed API.

Trust boundary: `Origin` is set by the browser but fully forgeable by an
attacker's page. Because cookies are sent, reflecting the request origin - or
answering "*" - would let any site read authenticated responses. Only an
exact match in the configured allow-list is echoed, and the value returned is
the configured one, never the raw header (no header injection).
"""

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _normalise(origin):
    """scheme://host[:port] -> canonical form, or None if it is not an origin."""
    if not isinstance(origin, str):
        return None
    value = origin.strip()
    if not value or len(value) > 2048:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return None
    scheme, sep, rest = value.partition("://")
    if not sep or not rest:
        return None
    scheme = scheme.lower()
    if scheme not in ("http", "https"):
        return None
    if "/" in rest or "@" in rest or "?" in rest or "#" in rest:
        return None
    host = rest.lower()
    if host.startswith("["):
        name, closing, port = host.partition("]")
        name = name + closing
        port = port[1:] if port.startswith(":") else ""
    else:
        name, _, port = host.partition(":")
    if not name:
        return None
    if port in ("", _DEFAULT_PORTS[scheme]):
        return scheme + "://" + name
    if not port.isdigit():
        return None
    return scheme + "://" + name + ":" + port


def cors_allow_origin(request_origin, allowed_origins):
    """Return the origin to echo, or None to omit the header."""
    requested = _normalise(request_origin)
    if requested is None:
        return None
    if not isinstance(allowed_origins, (list, tuple, set, frozenset)):
        return None

    for allowed in allowed_origins:
        if not isinstance(allowed, str):
            continue
        # A wildcard is never valid alongside credentials.
        if allowed.strip() == "*":
            continue
        if _normalise(allowed) == requested:
            return allowed.strip()
    return None
