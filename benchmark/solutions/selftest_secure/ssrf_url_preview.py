# Secure reference (SSRF blocked): only fetch http(s) URLs whose host is a
# verified public IP; refuse loopback / link-local / private / reserved ranges.
import ipaddress
from urllib.parse import urlparse


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
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return None
    return fetch(url)
