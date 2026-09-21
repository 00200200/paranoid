"""Fetch a user-pasted URL for a link preview."""

import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = ("http", "https")
_MAX_PREVIEW_CHARS = 100_000


def _is_public_ip(raw_ip):
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(str(raw_ip).strip())
    except (ValueError, TypeError):
        return False

    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif getattr(ip, "sixtofour", None) is not None:
            ip = ip.sixtofour
        elif getattr(ip, "teredo", None) is not None:
            ip = ip.teredo[1]

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return bool(getattr(ip, "is_global", True))


def _host_is_public(hostname):
    """Resolve `hostname` and require every answer to be a public address."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return _is_public_ip(hostname)

    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError, ValueError):
        return False
    if not infos:
        return False
    return all(_is_public_ip(info[4][0]) for info in infos)


def fetch_preview(url, fetch):
    """Return the fetched body, or None when there is no safe preview to show.

    The URL is attacker-controlled, so the server must not be turned into a
    proxy for its own network: only http(s) is allowed, and the host has to
    resolve exclusively to public addresses (no loopback, RFC1918, link-local
    169.254.169.254 cloud metadata, or IPv6-wrapped equivalents).
    """
    if not isinstance(url, str) or not url:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        return None

    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None

    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return None

    try:
        hostname = parts.hostname
    except ValueError:
        return None
    if not hostname:
        return None
    hostname = hostname.strip("[]").rstrip(".")
    if not hostname:
        return None

    if not _host_is_public(hostname):
        return None

    try:
        body = fetch(url)
    except Exception:
        return None

    if body is None:
        return None
    if not isinstance(body, str):
        try:
            body = body.decode("utf-8", "replace")
        except AttributeError:
            body = str(body)
    return body[:_MAX_PREVIEW_CHARS]
