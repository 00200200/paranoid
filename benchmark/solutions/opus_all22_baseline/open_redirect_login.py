"""Pick the post-login redirect target."""

from urllib.parse import urlsplit

_SITE_ROOT = "/"


def _host_of(value):
    """Return the lower-cased hostname of a host[:port] or full URL string."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if "://" not in text:
        text = "//" + text
    try:
        return (urlsplit(text).hostname or "").lower() or None
    except ValueError:
        return None


def safe_redirect_target(next_url, allowed_host):
    if not isinstance(next_url, str):
        return _SITE_ROOT

    candidate = next_url.strip()
    if not candidate:
        return _SITE_ROOT

    # Control characters would allow header/URL smuggling ("java\nscript:").
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return _SITE_ROOT

    # Browsers treat backslashes in the authority like forward slashes, so
    # analyse the normalised form ("/\evil.com" is "//evil.com").
    normalised = candidate.replace("\\", "/")
    try:
        parts = urlsplit(normalised)
    except ValueError:
        return _SITE_ROOT

    scheme = (parts.scheme or "").lower()
    if scheme and scheme not in ("http", "https"):
        # javascript:, data:, vbscript: ... never a redirect target.
        return _SITE_ROOT

    if parts.netloc:
        # An absolute (or protocol-relative) URL is only allowed when its host
        # really is ours. urlsplit's hostname ignores any "user@" prefix, so
        # "https://myapp.local@evil.com/" is correctly seen as evil.com.
        target_host = (parts.hostname or "").lower()
        expected_host = _host_of(allowed_host)
        if not target_host or not expected_host or target_host != expected_host:
            return _SITE_ROOT
        return candidate

    # No authority: only a rooted, same-site path is accepted.
    if normalised.startswith("/"):
        return candidate

    return _SITE_ROOT
