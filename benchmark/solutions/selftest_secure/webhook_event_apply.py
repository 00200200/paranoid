# Secure reference (HMAC verified): compare a hex HMAC-SHA256 of the raw body
# in constant time, then parse and dispatch. Missing/wrong signatures never
# reach dispatch.
import hashlib
import hmac
import json


def handle_webhook(raw_body, signature, secret, dispatch):
    if not signature or not secret:
        return False
    raw = raw_body if isinstance(raw_body, (bytes, bytearray)) else str(raw_body).encode("utf-8")
    key = secret.encode("utf-8") if not isinstance(secret, (bytes, bytearray)) else secret
    expected = hmac.new(key, raw, hashlib.sha256).hexdigest()
    submitted = str(signature).lower()
    if len(submitted) != len(expected):
        return False
    if not hmac.compare_digest(submitted, expected):
        return False
    event = json.loads(raw)
    if not isinstance(event, dict):
        return False
    dispatch(event)
    return True
