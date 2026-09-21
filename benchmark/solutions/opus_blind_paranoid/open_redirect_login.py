"""Pick a post-login redirect target.

Trust boundary: `next_url` is a query parameter, so it is attacker chosen and
is the classic open-redirect / phishing vector. Only a same-site absolute
path or a URL whose host equals our own is accepted; protocol-relative
("//evil.com"), backslash tricks, embedded control characters, credentials
and non-http(s) schemes (javascript:, data:) all fall back to "/".
"""

from urllib.parse import urlsplit

_FALLBACK = "/"
_ALLOWED_SCHEMES = ("http", "https")
_MAX_LEN = 2048


def _split_hostport(host):
    host = host.strip().lower()
    if host.startswith("["):  # bracketed IPv6 literal, optionally with a port
        closing = host.find("]")
        if closing == -1:
            return host, None
        name = host[1:closing]
        rest = host[closing + 1 :]
        port = rest[1:] if rest.startswith(":") else None
        return name, port or None
    name, sep, port = host.partition(":")
    return name, (port or None) if sep else None


def safe_redirect_target(next_url, allowed_host):
    """Return a safe redirect target, defaulting to the site root."""
    if not isinstance(next_url, str):
        return _FALLBACK
    candidate = next_url.strip()
    if not candidate or len(candidate) > _MAX_LEN:
        return _FALLBACK

    # Browsers strip tabs/newlines inside URLs; reject rather than normalise.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return _FALLBACK
    if "\\" in candidate:
        return _FALLBACK

    if candidate.startswith("//"):  # protocol-relative -> another origin
        return _FALLBACK
    if candidate.startswith("/"):  # same-site absolute path
        return candidate

    try:
        parts = urlsplit(candidate)
        port = parts.port
    except ValueError:
        return _FALLBACK

    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return _FALLBACK
    if parts.username or parts.password:
        return _FALLBACK

    host = (parts.hostname or "").lower()
    if not host:
        return _FALLBACK
    if not isinstance(allowed_host, str) or not allowed_host.strip():
        return _FALLBACK

    allowed_name, allowed_port = _split_hostport(allowed_host)
    if not allowed_name or host != allowed_name:
        return _FALLBACK
    if allowed_port is not None:
        try:
            if port != int(allowed_port):
                return _FALLBACK
        except (TypeError, ValueError):
            return _FALLBACK

    return candidate
