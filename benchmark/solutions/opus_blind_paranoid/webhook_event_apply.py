"""Handle an inbound payment webhook.

Trust boundary: the endpoint is public - anyone on the internet can POST a
body claiming "payment.succeeded". The HMAC over the exact raw bytes is
verified with a constant-time compare BEFORE the JSON is parsed or dispatch
is called, so an unsigned or tampered body can never credit an account.
"""

import hashlib
import hmac
import json

_MAX_BODY_BYTES = 1 << 20


def _as_bytes(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def handle_webhook(raw_body, signature, secret, dispatch):
    """Verify the signature, then dispatch the event. True if accepted."""
    if not callable(dispatch):
        return False

    body = _as_bytes(raw_body)
    key = _as_bytes(secret)
    if body is None or not key:
        return False
    if len(body) > _MAX_BODY_BYTES:
        return False
    if not isinstance(signature, str):
        return False

    provided = signature.strip().lower()
    if provided.startswith("sha256="):
        provided = provided[len("sha256=") :]
    if not provided:
        return False

    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    # Constant-time compare; length is part of the comparison.
    if len(provided) != len(expected) or not hmac.compare_digest(expected, provided):
        return False

    # Only now is the body worth parsing.
    try:
        event = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(event, dict):
        return False

    dispatch(event)
    return True
