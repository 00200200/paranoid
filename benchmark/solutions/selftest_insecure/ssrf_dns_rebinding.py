# Deliberately vulnerable reference (DNS rebinding / TOCTOU SSRF):
# Resolves the hostname once and checks the IP against private ranges,
# but fetches the original URL without pinning the IP, allowing DNS rebinding.
import ipaddress
from urllib.parse import urlparse

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def fetch_safe_url(url, resolve_host, fetch):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    hostname = parsed.hostname
    if not hostname:
        return None
    try:
        ips = resolve_host(hostname)
    except Exception:
        return None
    if not ips:
        return None
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
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
    # Vulnerability: fetches the URL without pinning the validated IP.
    # At fetch time, the HTTP client re-resolves the hostname, allowing
    # a DNS rebinding attack to redirect the request to an internal IP.
    return fetch(url)
