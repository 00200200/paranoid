"""Trust boundary: `next_url` is a query parameter, so an attacker can put any
string in a phishing link. Only a same-site relative path or an http(s) URL whose
host equals our own host is honoured; everything else falls back to "/".
"""

from urllib.parse import urlsplit

_SAFE_DEFAULT = "/"
_ALLOWED_SCHEMES = ("http", "https")
_MAX_URL = 2048


def _own_hostname(allowed_host):
    if not isinstance(allowed_host, str) or not allowed_host.strip():
        return None
    raw = allowed_host.strip()
    try:
        parsed = urlsplit(raw if "://" in raw else "//" + raw.lstrip("/"))
        host = parsed.hostname
    except ValueError:
        return None
    return host.lower() if host else None


def safe_redirect_target(next_url, allowed_host):
    own_host = _own_hostname(allowed_host)
    if not isinstance(next_url, str):
        return _SAFE_DEFAULT
    candidate = next_url.strip()
    if not candidate or len(candidate) > _MAX_URL:
        return _SAFE_DEFAULT
    # Backslashes, NULs, control characters and whitespace are all used to make
    # browsers and urlsplit disagree about where the host starts.
    if "\\" in candidate:
        return _SAFE_DEFAULT
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in candidate):
        return _SAFE_DEFAULT

    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        parts.port  # raises ValueError on a malformed port
        username, password = parts.username, parts.password
    except ValueError:
        return _SAFE_DEFAULT

    if parts.netloc:
        # Absolute or protocol-relative ("//evil.com") reference.
        if parts.scheme and parts.scheme.lower() not in _ALLOWED_SCHEMES:
            return _SAFE_DEFAULT
        if username is not None or password is not None:
            return _SAFE_DEFAULT  # https://myapp.local@evil.com style
        if not host or own_host is None or host.lower() != own_host:
            return _SAFE_DEFAULT
        return candidate

    if parts.scheme:
        return _SAFE_DEFAULT  # javascript:, data:, mailto:, file: ...
    if not candidate.startswith("/") or candidate.startswith("//"):
        return _SAFE_DEFAULT
    return candidate
