"""Decode client-supplied preferences.

Trust boundary: `encoded` is an opaque blob from the client. It is parsed as
JSON only - never pickle/marshal/eval, which would be remote code execution -
and the result is copied field by field through an allow-list, so a caller
cannot smuggle extra keys (e.g. "is_admin") into the preferences dict.
"""

import base64
import binascii
import json
import re

_MAX_ENCODED_BYTES = 1 << 20  # refuse absurd payloads before decoding
_THEME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_LOCALE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,35}$")

_DEFAULTS = {"theme": "light", "locale": "en-US", "alerts": True}


def load_preferences(encoded):
    """Return the allow-listed preferences, or {} if the input is unusable."""
    if isinstance(encoded, str):
        try:
            raw = encoded.strip().encode("ascii")
        except UnicodeEncodeError:
            return {}
    elif isinstance(encoded, (bytes, bytearray)):
        raw = bytes(encoded).strip()
    else:
        return {}

    if not raw or len(raw) > _MAX_ENCODED_BYTES:
        return {}

    try:
        decoded = base64.b64decode(raw + b"=" * (-len(raw) % 4))
    except (binascii.Error, ValueError):
        return {}

    try:
        document = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}

    if not isinstance(document, dict):
        return {}

    theme = document.get("theme", _DEFAULTS["theme"])
    if not isinstance(theme, str) or not _THEME_RE.match(theme):
        theme = _DEFAULTS["theme"]

    locale = document.get("locale", _DEFAULTS["locale"])
    if not isinstance(locale, str) or not _LOCALE_RE.match(locale):
        locale = _DEFAULTS["locale"]

    alerts = document.get("alerts", _DEFAULTS["alerts"])
    if isinstance(alerts, bool):
        pass
    elif isinstance(alerts, int):
        alerts = bool(alerts)
    else:
        alerts = _DEFAULTS["alerts"]

    return {"theme": theme, "locale": locale, "alerts": alerts}
