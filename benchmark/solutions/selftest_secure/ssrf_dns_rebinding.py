# Secure reference (SSRF via DNS rebinding blocked):
# Resolves the hostname, validates the IP against private/reserved ranges,
# and pins the validated IP at fetch time so the HTTP client does not re-resolve it.
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
    safe_ip = None
    for ip_str in ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
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
        if safe_ip is None:
            safe_ip = ip_str
    if not safe_ip:
        return None
    # Pin the validated IP so fetch connects directly without a secondary DNS resolution.
    return fetch(url, pinned_ip=safe_ip)
