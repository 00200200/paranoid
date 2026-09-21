"""Decode user preferences supplied as base64-encoded JSON."""

import base64
import binascii
import json

_DEFAULTS = {"theme": "light", "locale": "en-US", "alerts": True}

# Guard against absurdly large payloads before spending work on them.
_MAX_ENCODED_BYTES = 64 * 1024


def load_preferences(encoded):
    """Return the preferences dict, or {} when the input is unusable.

    The payload is decoded as JSON only -- never a pickle or other executable
    serialization format -- so a hostile blob can at worst be malformed data.
    """
    if isinstance(encoded, str):
        try:
            raw = encoded.encode("ascii")
        except UnicodeEncodeError:
            return {}
    elif isinstance(encoded, (bytes, bytearray)):
        raw = bytes(encoded)
    else:
        return {}

    if not raw or len(raw) > _MAX_ENCODED_BYTES:
        return {}

    # Tolerate the whitespace some base64 encoders insert, and accept either the
    # standard or the URL-safe alphabet.
    raw = b"".join(raw.split())
    raw += b"=" * (-len(raw) % 4)
    decoded = None
    for alphabet in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = alphabet(raw)
            break
        except (binascii.Error, ValueError):
            continue
    if decoded is None:
        return {}

    try:
        data = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}

    if not isinstance(data, dict):
        return {}

    theme = data.get("theme", _DEFAULTS["theme"])
    locale = data.get("locale", _DEFAULTS["locale"])
    alerts = data.get("alerts", _DEFAULTS["alerts"])

    return {
        "theme": theme if isinstance(theme, str) else _DEFAULTS["theme"],
        "locale": locale if isinstance(locale, str) else _DEFAULTS["locale"],
        "alerts": alerts if isinstance(alerts, bool) else _DEFAULTS["alerts"],
    }
