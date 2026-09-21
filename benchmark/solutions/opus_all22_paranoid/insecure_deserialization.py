"""Trust boundary: `encoded` is an untrusted blob straight off the wire. It is
parsed as JSON only -- never pickle/marshal/yaml, which would turn a preferences
blob into remote code execution -- and every field is type-checked and bounded.
"""

import base64
import binascii
import json

_MAX_ENCODED = 64 * 1024  # bound the work an anonymous caller can cause
_DEFAULTS = {"theme": "light", "locale": "en-US", "alerts": True}


def _b64decode(raw):
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        pass
    try:  # tolerate url-safe / unpadded encodings, still data-only
        padded = raw + b"=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return None


def load_preferences(encoded):
    if isinstance(encoded, str):
        try:
            raw = encoded.encode("ascii")
        except UnicodeEncodeError:
            return {}
    elif isinstance(encoded, (bytes, bytearray)):
        raw = bytes(encoded)
    else:
        return {}

    if not raw or len(raw) > _MAX_ENCODED:
        return {}

    decoded = _b64decode(raw)
    if decoded is None:
        return {}

    try:
        data = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}

    prefs = dict(_DEFAULTS)
    theme = data.get("theme")
    if isinstance(theme, str) and 0 < len(theme) <= 64:
        prefs["theme"] = theme
    locale = data.get("locale")
    if isinstance(locale, str) and 0 < len(locale) <= 35:
        prefs["locale"] = locale
    alerts = data.get("alerts")
    if isinstance(alerts, bool):
        prefs["alerts"] = alerts
    return prefs
