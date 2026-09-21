"""Fetch a link preview for a user-supplied URL."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = ("http", "https")

_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)

_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
    ".corp",
    ".private",
    ".home.arpa",
)

_DEC_RE = re.compile(r"\A[0-9]+\Z")
_HEX_RE = re.compile(r"\A0[xX][0-9a-fA-F]+\Z")
_OCT_RE = re.compile(r"\A0[0-7]+\Z")


def _as_int(part):
    if _HEX_RE.match(part):
        return int(part, 16)
    if _OCT_RE.match(part):
        return int(part, 8)
    if _DEC_RE.match(part):
        return int(part, 10)
    return None


def _literal_ip(host):
    """Parse an address literal, including the decimal/hex/octal spellings
    of IPv4 that are used to slip past naive string checks."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    pieces = host.split(".")
    if len(pieces) == 1:
        value = _as_int(pieces[0])
        if value is not None and 0 <= value <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(value)
        return None

    if len(pieces) == 4:
        octets = [_as_int(p) for p in pieces]
        if all(o is not None and 0 <= o <= 0xFF for o in octets):
            return ipaddress.IPv4Address(
                (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
            )
    return None


def _addresses_to_check(ip):
    found = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour):
            if embedded is not None:
                found.append(embedded)
        if ip.teredo is not None:
            found.extend(ip.teredo)
    return found


def _is_public_ip(ip):
    if isinstance(ip, str):
        try:
            ip = ipaddress.ip_address(ip)
        except ValueError:
            return False
    for address in _addresses_to_check(ip):
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local     # 169.254.169.254 cloud metadata
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.is_site_local:
            return False
        if not address.is_global:
            return False
    return True


def fetch_preview(url, fetch):
    if not isinstance(url, str) or not url.strip():
        return None

    candidate = url.strip()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return None

    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None

    # Only real web requests: file://, gopher://, ftp://, data:, ... are the
    # classic ways to turn a fetcher into a local file reader.
    if (parts.scheme or "").lower() not in _ALLOWED_SCHEMES:
        return None

    try:
        hostname = parts.hostname
    except ValueError:
        return None
    if not hostname:
        return None
    hostname = hostname.strip().strip(".").lower()
    if not hostname:
        return None

    if hostname in _BLOCKED_HOSTS or hostname.endswith(_BLOCKED_SUFFIXES):
        return None

    literal = _literal_ip(hostname)
    if literal is not None:
        if not _is_public_ip(literal):
            return None
    else:
        # A bare single-label name is an intranet host, not a public site.
        if "." not in hostname:
            return None
        try:
            infos = socket.getaddrinfo(
                hostname, parts.port or (443 if parts.scheme.lower() == "https" else 80),
                proto=socket.IPPROTO_TCP,
            )
        except (socket.gaierror, UnicodeError, ValueError):
            # The name does not resolve here; there is nothing to fetch and
            # nothing to leak. Leave the request to the fetcher, which will
            # fail the same way.
            infos = []
        except OSError:
            infos = []

        for info in infos:
            address = info[4][0]
            # Every answer has to be public: a name that resolves to a mix of
            # public and internal addresses is not safe to request.
            if not _is_public_ip(str(address).split("%")[0]):
                return None

    try:
        return fetch(candidate)
    except Exception:
        return None
