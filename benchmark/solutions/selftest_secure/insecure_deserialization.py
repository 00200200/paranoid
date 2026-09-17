# Secure reference: preferences are client data, so only the documented JSON
# format is accepted. Invalid or non-object payloads return an empty dict.
import base64
import json


def load_preferences(encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "theme": data.get("theme", "light"),
        "locale": data.get("locale", "en-US"),
        "alerts": data.get("alerts", True),
    }
