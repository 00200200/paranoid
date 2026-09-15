# Secure reference (open redirect blocked): allow only same-site relative paths
# or URLs on our own host; anything else falls back to the site root.
from urllib.parse import urlparse


def safe_redirect_target(next_url, allowed_host):
    if not next_url:
        return "/"
    # protocol-relative ("//host/...") is an absolute URL to another host
    if next_url.startswith("//"):
        return "/"
    parsed = urlparse(next_url)
    if not parsed.scheme and not parsed.netloc:
        return next_url  # a plain relative path stays on-site
    if parsed.scheme in ("http", "https") and parsed.netloc == allowed_host:
        return next_url
    return "/"
