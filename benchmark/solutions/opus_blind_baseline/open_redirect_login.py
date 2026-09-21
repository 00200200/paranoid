"""Validate the post-login redirect target."""

from urllib.parse import urlsplit

_SITE_ROOT = "/"


def _host_matches(netloc, allowed_host):
    """Compare a URL's netloc with our own host, rejecting userinfo tricks."""
    if "@" in netloc:
        # e.g. "myapp.local@evil.example" -- the browser goes to evil.example.
        return False
    netloc = netloc.lower()
    allowed = allowed_host.lower()
    if netloc == allowed:
        return True
    # Allow "host" to match a configured "host:port" and vice versa.
    host_only = netloc.rsplit(":", 1)[0] if netloc.count(":") == 1 else netloc
    allowed_only = allowed.rsplit(":", 1)[0] if allowed.count(":") == 1 else allowed
    return bool(host_only) and host_only == allowed_only


def safe_redirect_target(next_url, allowed_host):
    """Return a redirect target on our own site, or "/" for anything else."""
    if not isinstance(next_url, str) or not next_url:
        return _SITE_ROOT
    if not isinstance(allowed_host, str) or not allowed_host:
        return _SITE_ROOT

    candidate = next_url.strip()
    if not candidate:
        return _SITE_ROOT

    # Control characters (NUL, CR, LF, tab) enable header injection and are also
    # stripped by browsers when resolving a URL, which defeats naive prefix checks.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in candidate):
        return _SITE_ROOT

    # Browsers treat backslashes in the authority position as slashes, so
    # "/\evil.example" and "\\evil.example" are off-site. Normalize before
    # inspecting, but redirect to the original string only if it passes.
    probe = candidate.replace("\\", "/")

    if probe.startswith("//"):
        # Protocol-relative URL: the authority decides the destination.
        return _SITE_ROOT
    if probe.startswith("/"):
        # A plain same-site path.
        return candidate

    parts = urlsplit(probe)
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        # javascript:, data:, vbscript:, file: ...
        return _SITE_ROOT
    if parts.netloc:
        if parts.scheme.lower() in ("http", "https") and _host_matches(
            parts.netloc, allowed_host
        ):
            return candidate
        return _SITE_ROOT

    # No scheme and no authority: a relative path such as "dashboard?x=1".
    if parts.scheme:
        return _SITE_ROOT
    return candidate
