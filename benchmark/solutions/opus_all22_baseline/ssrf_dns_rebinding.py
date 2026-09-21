"""Fetch a URL on a user's behalf, resolving and pinning the hostname."""

import ipaddress
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = ("http", "https")


def _addresses_to_check(ip):
    """The address itself plus any IPv4 address embedded in it."""
    found = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour):
            if embedded is not None:
                found.append(embedded)
        if ip.teredo is not None:
            found.extend(ip.teredo)
    return found


def _is_public_ip(value):
    """True only for a globally routable unicast address."""
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except (ValueError, TypeError):
        return False

    for ip in _addresses_to_check(parsed):
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local          # 169.254.0.0/16 -> cloud metadata
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
            return False
        if not ip.is_global:             # also drops CGNAT and benchmark ranges
            return False
    return True


def fetch_safe_url(url, resolve_host, fetch):
    if not isinstance(url, str) or not url.strip():
        return None

    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None

    if (parts.scheme or "").lower() not in _ALLOWED_SCHEMES:
        return None

    try:
        hostname = parts.hostname
    except ValueError:
        return None
    if not hostname:
        return None

    # A literal address needs no lookup, just the same policy check.
    try:
        ipaddress.ip_address(hostname)
        is_literal = True
    except ValueError:
        is_literal = False

    if is_literal:
        if not _is_public_ip(hostname):
            return None
        pinned = hostname
    else:
        try:
            addresses = resolve_host(hostname)
        except Exception:
            return None
        if isinstance(addresses, (str, bytes)):
            addresses = [addresses]
        try:
            addresses = [str(a) for a in addresses]
        except TypeError:
            return None
        if not addresses:
            return None

        # Every answer must be acceptable: one private address in the set is
        # enough for an attacker to win the race.
        for address in addresses:
            if not _is_public_ip(address):
                return None
        pinned = addresses[0]

    # Connect to the address we validated instead of letting the fetch resolve
    # the name a second time. Without this pin the DNS answer can flip between
    # the check and the request (rebinding), and the "public" host we approved
    # becomes 127.0.0.1 or 169.254.169.254 by the time the socket opens.
    try:
        return fetch(url, pinned_ip=pinned)
    except Exception:
        return None
