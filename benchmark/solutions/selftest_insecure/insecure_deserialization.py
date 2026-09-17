# Deliberately vulnerable reference: invalid JSON falls back to pickle, so a
# client-controlled preferences blob can execute code during deserialization.
import base64
import json
import pickle


def _normalize(data):
    if not isinstance(data, dict):
        data = {}
    return {
        "theme": data.get("theme", "light"),
        "locale": data.get("locale", "en-US"),
        "alerts": data.get("alerts", True),
    }


def load_preferences(encoded):
    raw = base64.b64decode(encoded)
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        data = pickle.loads(raw)  # VULNERABLE: untrusted client data reaches pickle
    return _normalize(data)
