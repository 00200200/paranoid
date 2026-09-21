"""Fetch a user-supplied URL (SSRF-hardened, with DNS rebinding defence).

Trust boundary: `url` is fully attacker controlled, and the server sits
inside a private network next to cloud metadata (169.254.169.254) and
internal admin ports. Only http/https is allowed; every address the hostname
resolves to must be a public unicast address; and the fetch is pinned to the
address that was validated, so a DNS name that flips to 127.0.0.1 between
the check and the connection (rebinding) cannot win the race.
"""

import ipaddress
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = ("http", "https")
_MAX_URL_LEN = 2048

_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
)
_BLOCKED_NAMES = frozenset({"localhost", "metadata.google.internal", "metadata"})


def _is_public_ip(value):
    """True only for a globally routable unicast address."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError):
        return False
    # Unwrap IPv4-in-IPv6 forms so ::ffff:127.0.0.1 cannot slip through.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    sixtofour = getattr(ip, "sixtofour", None)
    if sixtofour is not None:
        ip = sixtofour
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return bool(ip.is_global)


def _blocked_name(host):
    name = host.strip(".").lower()
    if not name or name in _BLOCKED_NAMES:
        return True
    return name.endswith(_BLOCKED_SUFFIXES)


def fetch_safe_url(url, resolve_host, fetch):
    """Fetch `url` if it points at a public host, else return None."""
    if not isinstance(url, str) or not callable(resolve_host) or not callable(fetch):
        return None
    target = url.strip()
    if not target or len(target) > _MAX_URL_LEN:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target):
        return None

    try:
        parts = urlsplit(target)
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        return None

    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return None
    if parts.username or parts.password:
        return None

    host = parts.hostname
    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False

    if is_literal:
        if not _is_public_ip(host):
            return None
        addresses = [host]
    else:
        if _blocked_name(host):
            return None
        try:
            resolved = resolve_host(host)
        except Exception:
            return None
        if not resolved or not isinstance(resolved, (list, tuple, set)):
            return None
        addresses = [str(item).strip() for item in resolved]
        # Every answer must be public: one private A record is enough to abuse.
        if not all(_is_public_ip(address) for address in addresses):
            return None

    try:
        return fetch(target, pinned_ip=addresses[0])
    except Exception:
        return None
