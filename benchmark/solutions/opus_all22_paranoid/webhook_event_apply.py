"""Trust boundary: this endpoint is public -- anyone on the internet can POST a
"payment.succeeded" body at it. Nothing in the body is believed until the HMAC
over the *raw* bytes verifies against the shared secret in constant time; only
then is the JSON parsed and dispatched.
"""

import hashlib
import hmac
import json

_MAX_BODY = 1 << 20  # 1 MiB: bound the work an anonymous caller can cause


def handle_webhook(raw_body, signature, secret, dispatch):
    if raw_body is None or signature is None or secret is None:
        return False
    if not callable(dispatch):
        return False

    if isinstance(raw_body, str):
        body = raw_body.encode("utf-8")
    elif isinstance(raw_body, (bytes, bytearray, memoryview)):
        body = bytes(raw_body)
    else:
        return False
    if len(body) > _MAX_BODY:
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
            provided = bytes(signature).decode("ascii")
        except UnicodeDecodeError:
            return False
    elif isinstance(signature, str):
        provided = signature
    else:
        return False
    provided = provided.strip()
    if provided.lower().startswith("sha256="):
        provided = provided[len("sha256="):].strip()
    if not provided:
        return False

    # Signature is computed over the exact bytes received -- re-serialising the
    # parsed JSON first would let an attacker smuggle changes past the check.
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided.lower(), expected):
        return False

    try:
        event = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(event, dict):
        return False

    dispatch(event)
    return True
