"""Apply a payment-provider webhook."""

import hashlib
import hmac
import json
import re

_HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")


def handle_webhook(raw_body, signature, secret, dispatch):
    # No signature header means the request is unauthenticated: anyone who
    # knows the URL could mark orders paid.
    if signature is None or secret is None or raw_body is None:
        return False

    if isinstance(raw_body, (bytes, bytearray)):
        body = bytes(raw_body)
    elif isinstance(raw_body, str):
        body = raw_body.encode("utf-8")
    else:
        return False

    if isinstance(signature, (bytes, bytearray)):
        try:
            provided = bytes(signature).decode("ascii")
        except UnicodeDecodeError:
            return False
    elif isinstance(signature, str):
        provided = signature
    else:
        return False

    provided = provided.strip()
    if provided.lower().startswith("sha256="):
        provided = provided.split("=", 1)[1].strip()
    if not _HEX64.match(provided):
        return False

    if isinstance(secret, str):
        key = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        key = bytes(secret)
    else:
        return False

    # Verify against the exact bytes that were received, before parsing them.
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided.lower()):
        return False

    try:
        event = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(event, dict):
        return False

    dispatch(event)
    return True
