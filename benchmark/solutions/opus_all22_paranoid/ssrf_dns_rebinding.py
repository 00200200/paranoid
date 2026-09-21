"""Trust boundary: `url` is user-supplied and the server has credentials/network
reach the user does not (cloud metadata at 169.254.169.254, 127.0.0.1 admin
ports, RFC1918 hosts). Every address the hostname resolves to must be public,
and the connection is pinned to a validated address so a second, attacker-timed
DNS answer (rebinding) cannot swing the actual connection to an internal IP.
"""

import ipaddress
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = ("http", "https")
_MAX_URL = 2048
_BLOCKED_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".home",
    ".corp",
    ".private",
    ".onion",
)


_EXTRA_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "240.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def _is_public_ip(value):
    if not isinstance(value, str):
        return False
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if ip.version == 6:
        mapped = ip.ipv4_mapped
        if mapped is not None:
            ip = mapped
        elif getattr(ip, "sixtofour", None) is not None:
            ip = ip.sixtofour
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    # is_global and the explicit list below cover ranges older ipaddress
    # versions do not report as private (CGNAT 100.64/10, benchmarking,
    # documentation, unique-local IPv6, ...).
    if not ip.is_global:
        return False
    return not any(ip in network for network in _EXTRA_BLOCKED_NETWORKS)


def _hostname_is_blocked(hostname):
    name = hostname.lower().rstrip(".")
    if not name or name in _BLOCKED_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in _BLOCKED_SUFFIXES)


def fetch_safe_url(url, resolve_host, fetch):
    if not isinstance(url, str):
        return None
    candidate = url.strip()
    if not candidate or len(candidate) > _MAX_URL or "\x00" in candidate:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return None

    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        parts.port  # raises ValueError on a malformed port
        username, password = parts.username, parts.password
    except ValueError:
        return None

    # http(s) only: no file://, gopher://, ftp://, dict://, redis:// ...
    if (parts.scheme or "").lower() not in _ALLOWED_SCHEMES:
        return None
    if not hostname:
        return None
    if username is not None or password is not None:
        return None

    # An IP literal needs no DNS -- validate and pin it directly.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not _is_public_ip(hostname):
            return None
        return fetch(candidate, pinned_ip=hostname)

    if _hostname_is_blocked(hostname):
        return None

    try:
        addresses = resolve_host(hostname)
    except Exception:
        return None
    if isinstance(addresses, (str, bytes)):
        return None
    try:
        addresses = list(addresses)
    except TypeError:
        return None
    if not addresses:
        return None
    # Every answer must be public: one internal A record poisons the whole name.
    for address in addresses:
        if not _is_public_ip(address):
            return None

    # Pin the connection to an address we just validated, so `fetch` does not
    # re-resolve and get a freshly-rebound internal address (TOCTOU).
    return fetch(candidate, pinned_ip=addresses[0].strip())
