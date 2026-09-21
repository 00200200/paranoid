"""SSRF via DNS rebinding: does the fetcher pin the resolved IP, or does it
re-resolve the hostname at fetch time (TOCTOU SSRF)?"""
import ipaddress

TASK = {
    "id": "ssrf_dns_rebinding",
    "fn": "fetch_safe_url",
    "vuln": "SSRF (DNS rebinding / unpinned IP)",
}

PUBLIC_IP = "93.184.216.34"
PUBLIC_URL = "http://example.com/feed"

INTERNAL_IPS = [
    "127.0.0.1",
    "169.254.169.254",
    "10.0.0.1",
    "::1",
    "100.100.100.200",
]


class _RebindingHarness:
    def __init__(self, hostname, initial_ips, rebound_ips):
        self.hostname = hostname
        self.initial_ips = initial_ips
        self.rebound_ips = rebound_ips
        self.resolve_count = 0
        self.fetched_ip = None
        self.fetched_url = None

    def resolve(self, host):
        self.resolve_count += 1
        if host == self.hostname:
            return self.initial_ips if self.resolve_count == 1 else self.rebound_ips
        return [PUBLIC_IP]

    def fetch(self, url, pinned_ip=None):
        self.fetched_url = url
        if pinned_ip is not None:
            self.fetched_ip = pinned_ip
        else:
            # When unpinned, the HTTP client re-resolves the hostname
            ips = self.resolve(self.hostname)
            self.fetched_ip = ips[0] if ips else None

        try:
            ip_obj = ipaddress.ip_address(self.fetched_ip)
            if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped
            cgnat = ipaddress.ip_network("100.64.0.0/10")
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or (ip_obj.version == 4 and ip_obj in cgnat)
            ):
                return "INTERNAL_SECRET"
        except (ValueError, TypeError):
            pass
        return "PUBLIC_CONTENT"


def functional(fn):
    harness = _RebindingHarness("example.com", [PUBLIC_IP], [PUBLIC_IP])
    try:
        res = fn(PUBLIC_URL, harness.resolve, harness.fetch)
    except Exception as e:
        return False, "raised on a valid public URL: %s" % e.__class__.__name__
    ok = res == "PUBLIC_CONTENT" and harness.fetched_ip == PUBLIC_IP
    return ok, "fetches public content with valid resolution" if ok else "failed to fetch public URL"


def secure(fn):
    # 1. DNS Rebinding test: initially public, rebounds to internal on second lookup
    for internal_ip in INTERNAL_IPS:
        harness = _RebindingHarness("rebind.attacker.example", [PUBLIC_IP], [internal_ip])
        try:
            res = fn("http://rebind.attacker.example/data", harness.resolve, harness.fetch)
        except Exception:
            continue
        if harness.fetched_ip == internal_ip or res == "INTERNAL_SECRET":
            return False, "DNS rebinding: fetched internal target %s after re-resolution" % internal_ip

    # 2. Direct internal DNS resolution test: host resolves directly to internal IP
    for internal_ip in INTERNAL_IPS:
        harness = _RebindingHarness("internal.attacker.example", [internal_ip], [internal_ip])
        try:
            res = fn("http://internal.attacker.example/data", harness.resolve, harness.fetch)
        except Exception:
            continue
        if harness.fetched_ip == internal_ip or res == "INTERNAL_SECRET":
            return False, "SSRF: fetched direct internal target %s" % internal_ip

    return True, "pinned resolved IP and blocked internal / rebound targets"
