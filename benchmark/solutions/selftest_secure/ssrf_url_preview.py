# Secure reference (SSRF blocked): only fetch http(s) URLs whose host is a
# verified public IP; refuse loopback / link-local / private / reserved / CGNAT.
import ipaddress
from urllib.parse import urlparse

# RFC 6598 shared address space. ipaddress.is_private does not cover it, and
# cloud metadata (e.g. Alibaba 100.100.100.200) sits in this range.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def fetch_preview(url, fetch):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    host = parsed.hostname
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None  # this feature only previews explicit public IP literals
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) must be judged as the embedded v4 address.
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or (ip.version == 4 and ip in _CGNAT)
    ):
        return None
    return fetch(url)
