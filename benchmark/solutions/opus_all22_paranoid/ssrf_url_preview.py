"""Trust boundary: a user pastes any URL and the server fetches it from inside
the network. Treat it as hostile: http(s) only, no credentials in the URL, no
internal hostnames, and every address the name resolves to must be a public
one -- otherwise the "preview" becomes a read of cloud metadata or localhost.
"""

import ipaddress
import socket
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


def fetch_preview(url, fetch):
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
        port = parts.port
        username, password = parts.username, parts.password
    except ValueError:
        return None

    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return None  # blocks file://, gopher://, ftp://, dict:// ...
    if not hostname:
        return None
    if username is not None or password is not None:
        return None

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        # A literal IP: allowed only if it is public.
        return fetch(candidate) if _is_public_ip(hostname) else None

    if _hostname_is_blocked(hostname):
        return None

    try:
        infos = socket.getaddrinfo(
            hostname, port or (443 if scheme == "https" else 80),
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        # No DNS available here; fall back to a conservative name check so that
        # single-label / internal-looking hosts are still refused.
        if "." not in hostname.strip("."):
            return None
        infos = None
    except (OSError, UnicodeError, ValueError):
        return None

    if infos is not None:
        if not infos:
            return None
        for info in infos:
            if not _is_public_ip(info[4][0]):
                return None

    return fetch(candidate)
