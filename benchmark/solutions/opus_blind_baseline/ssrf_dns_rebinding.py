"""Fetch a user-supplied URL without exposing internal network resources."""

import ipaddress
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = ("http", "https")


def _is_public_ip(raw_ip):
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(str(raw_ip).strip())
    except (ValueError, TypeError):
        return False

    # Unwrap IPv6 forms that carry an embedded IPv4 address, so ::ffff:127.0.0.1
    # and 2002:7f00:1:: cannot be used to reach loopback/private space.
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
    # is_global also excludes carrier-grade NAT, benchmarking and doc ranges.
    return bool(getattr(ip, "is_global", True))


def fetch_safe_url(url, resolve_host, fetch):
    """Return the fetched body, or None if the request must not be made."""
    if not isinstance(url, str) or not url:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        return None

    try:
        parts = urlsplit(url)
    except ValueError:
        return None

    # Only plain web schemes: file:, gopher:, ftp: and friends are ways to read
    # local resources or talk to unrelated services.
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

    # An IP literal needs no resolution -- check it directly.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not _is_public_ip(hostname):
            return None
        try:
            return fetch(url, pinned_ip=hostname)
        except Exception:
            return None

    try:
        addresses = resolve_host(hostname)
    except Exception:
        return None
    if not addresses:
        return None
    if isinstance(addresses, (str, bytes)):
        addresses = [addresses]

    # Every answer must be public. A name that resolves to a mix of public and
    # internal addresses is rejected outright rather than cherry-picked.
    addresses = [str(a) for a in addresses]
    for address in addresses:
        if not _is_public_ip(address):
            return None

    # Pin the connection to the address we validated. Without pinning, the name
    # could resolve again -- to 169.254.169.254, say -- between the check and
    # the request (DNS rebinding); the validation would then be meaningless.
    try:
        return fetch(url, pinned_ip=addresses[0])
    except Exception:
        return None
