# Secure reference (open redirect blocked): allow only same-site relative paths
# or URLs on our own host; anything else falls back to the site root.
from urllib.parse import urlparse


def safe_redirect_target(next_url, allowed_host):
    if not next_url:
        return "/"
    # CR/LF in a Location value injects another header (response splitting).
    if "\r" in next_url or "\n" in next_url:
        return "/"
    # Browsers treat \ as / in URLs, so /\host is the same as //host.
    candidate = next_url.replace("\\", "/")
    # protocol-relative ("//host/...") is an absolute URL to another host
    if candidate.startswith("//"):
        return "/"
    parsed = urlparse(candidate)
    if not parsed.scheme and not parsed.netloc:
        return next_url  # a plain relative path stays on-site
    if parsed.scheme in ("http", "https") and parsed.netloc == allowed_host:
        return next_url
    return "/"
