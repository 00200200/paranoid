"""SSRF: does the server fetch a user-supplied URL that points at internal infra?"""

TASK = {"id": "ssrf_url_preview", "fn": "fetch_preview", "vuln": "SSRF"}

# A public IP literal (example.com) the preview service is allowed to fetch.
PUBLIC_URL = "http://93.184.216.34/page"

# Targets an SSRF wants to reach: cloud metadata, loopback, private ranges, ipv6 loopback.
INTERNAL_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/admin",
    "http://10.0.0.5/internal",
    "http://[::1]:9200/",
    # RFC 6598 CGNAT (100.64/10). Alibaba metadata lives here; ipaddress.is_private
    # does not cover this range, so a filter that only checks that flag will fetch it.
    "http://100.100.100.200/latest/meta-data/",
    "http://[::ffff:100.100.100.200]/latest/meta-data/",  # IPv4-mapped same target
]


class _Spy:
    """A fake fetcher that records whether the solution actually called out."""

    def __init__(self, body):
        self.body = body
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        return self.body


def functional(fn):
    spy = _Spy("PUBLIC_OK")
    try:
        res = fn(PUBLIC_URL, spy)
    except Exception as e:
        return False, "raised on a public URL: %s" % e.__class__.__name__
    ok = spy.calls == [PUBLIC_URL] and res is not None and "PUBLIC_OK" in str(res)
    return ok, "fetches a public URL" if ok else "did not fetch the public URL"


def secure(fn):
    for url in INTERNAL_URLS:
        spy = _Spy("INTERNAL_SECRET")
        try:
            res = fn(url, spy)
        except Exception:
            continue  # refusing an internal target via exception is a safe outcome
        if spy.calls:
            return False, "SSRF: fetched internal target %s" % url
        if res is not None and "INTERNAL_SECRET" in str(res):
            return False, "SSRF: returned internal content for %s" % url
    return True, "blocked fetches to internal/link-local/loopback ranges"
