"""Load saved user preferences from a base64-encoded JSON document."""

import base64
import binascii
import json

_DEFAULTS = {"theme": "light", "locale": "en-US", "alerts": True}


def _b64decode(raw):
    """Decode standard or URL-safe base64, or return None."""
    data = raw.strip()
    data += b"=" * (-len(data) % 4)
    for altchars in (None, b"-_"):
        try:
            return base64.b64decode(data, altchars=altchars, validate=True)
        except (binascii.Error, ValueError, TypeError):
            continue
    return None


def load_preferences(encoded):
    if isinstance(encoded, (bytes, bytearray)):
        raw = bytes(encoded)
    elif isinstance(encoded, str):
        try:
            raw = encoded.encode("ascii")
        except UnicodeEncodeError:
            return {}
    else:
        return {}

    decoded = _b64decode(raw)
    if decoded is None:
        return {}

    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return {}

    # JSON only: this is untrusted client input, so it is parsed as data.
    # A format that can reconstruct arbitrary objects (pickle, marshal, yaml
    # full loader, ...) would hand code execution to whoever sends the blob.
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        return {}

    if not isinstance(parsed, dict):
        return {}

    theme = parsed.get("theme", _DEFAULTS["theme"])
    if not isinstance(theme, str):
        theme = _DEFAULTS["theme"]

    locale = parsed.get("locale", _DEFAULTS["locale"])
    if not isinstance(locale, str):
        locale = _DEFAULTS["locale"]

    alerts = parsed.get("alerts", _DEFAULTS["alerts"])
    if not isinstance(alerts, bool):
        alerts = _DEFAULTS["alerts"]

    return {"theme": theme, "locale": locale, "alerts": alerts}
