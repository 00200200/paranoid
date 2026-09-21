"""Handle an incoming signed payment webhook."""

import hashlib
import hmac
import json


def handle_webhook(raw_body, signature, secret, dispatch):
    """Verify the signature, then dispatch the event. Return True if accepted.

    Anyone on the internet can POST to a webhook endpoint, so the HMAC is the
    only thing proving the event came from the payment provider. It is verified
    over the exact bytes received -- before parsing -- and compared in constant
    time. An unsigned or mismatched request is dropped without calling dispatch.
    """
    if signature is None:
        return False
    if raw_body is None:
        return False

    if isinstance(raw_body, str):
        body = raw_body.encode("utf-8")
    elif isinstance(raw_body, (bytes, bytearray)):
        body = bytes(raw_body)
    else:
        return False

    if isinstance(secret, str):
        key = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        key = bytes(secret)
    else:
        return False
    if not key:
        return False

    if isinstance(signature, (bytes, bytearray)):
        try:
            provided = signature.decode("ascii")
        except UnicodeDecodeError:
            return False
    elif isinstance(signature, str):
        provided = signature
    else:
        return False

    provided = provided.strip()
    if not provided:
        return False

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
