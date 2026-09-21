"""Trust boundary: `Origin` is set by the browser but fully forgeable by any
site. Because the API sends credentials, "*" is illegal and reflecting whatever
arrived would hand every origin an authenticated read. Only an exact match
against the configured allow-list is echoed back.
"""

from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize(origin):
    if not isinstance(origin, str):
        return None
    value = origin.strip().rstrip("/")
    if not value or value == "*" or value.lower() == "null":
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    if parts.path or parts.query or parts.fragment:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return scheme + "://" + host.lower()
    return "{}://{}:{}".format(scheme, host.lower(), port)


def cors_allow_origin(request_origin, allowed_origins):
    requested = _normalize(request_origin)
    if requested is None:
        return None
    if not allowed_origins or isinstance(allowed_origins, (str, bytes)):
        return None
    try:
        candidates = list(allowed_origins)
    except TypeError:
        return None
    for allowed in candidates:
        if not isinstance(allowed, str) or allowed.strip() == "*":
            continue  # never widen to a wildcard on a credentialed endpoint
        if _normalize(allowed) == requested:
            return allowed.strip()
    return None
