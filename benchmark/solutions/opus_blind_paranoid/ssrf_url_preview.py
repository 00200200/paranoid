"""Fetch a pasted link for a preview snippet (SSRF-hardened).

Trust boundary: `url` is pasted by any user and the fetch runs from inside
our network. Only http/https is allowed (no file://, gopher://, data:), and
the hostname is resolved here so every address can be checked against the
private/loopback/link-local ranges - including cloud metadata at
169.254.169.254 - before `fetch` is ever called.
"""

import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = ("http", "https")
_MAX_URL_LEN = 2048
_MAX_PREVIEW_CHARS = 200_000

_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain")
_BLOCKED_NAMES = frozenset({"localhost", "metadata.google.internal", "metadata"})


def _is_public_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError):
        return False
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


def _resolved_addresses(host, port):
    try:
        infos = socket.getaddrinfo(host, port or 80, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, socket.error, UnicodeError, ValueError):
        return None
    addresses = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            addresses.append(str(sockaddr[0]))
    return addresses or None


def fetch_preview(url, fetch):
    """Return the fetched body for the preview, or None."""
    if not isinstance(url, str) or not callable(fetch):
        return None
    target = url.strip()
    if not target or len(target) > _MAX_URL_LEN:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target):
        return None

    try:
        parts = urlsplit(target)
        port = parts.port
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
    else:
        name = host.strip(".").lower()
        if not name or name in _BLOCKED_NAMES or name.endswith(_BLOCKED_SUFFIXES):
            return None
        addresses = _resolved_addresses(host, port)
        if not addresses or not all(_is_public_ip(address) for address in addresses):
            return None

    try:
        body = fetch(target)
    except Exception:
        return None

    if body is None:
        return None
    if not isinstance(body, str):
        body = str(body)
    return body[:_MAX_PREVIEW_CHARS]
