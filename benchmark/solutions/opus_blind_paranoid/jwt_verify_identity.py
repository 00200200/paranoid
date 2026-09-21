"""Authenticate a request from its JWT.

Trust boundary: the whole token is attacker supplied, header included. The
signature is verified before any claim is trusted, the algorithm must be
HS256 (so `alg: none` and RS256->HS256 confusion are rejected), the compare
is constant time, and exp/nbf are honoured.
"""

import base64
import binascii
import hashlib
import hmac
import json
import time

_MAX_TOKEN_CHARS = 8192
_LEEWAY_SECONDS = 0


def _b64url_decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _json_segment(segment):
    return json.loads(_b64url_decode(segment).decode("utf-8"))


def _numeric_claim(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def user_from_token(token, secret):
    """Return the `sub` claim of a valid HS256 token, else None."""
    if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN_CHARS:
        return None
    if isinstance(secret, str):
        key = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        key = bytes(secret)
    else:
        return None
    if not key:
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64 or not signature_b64:
        return None

    try:
        header = _json_segment(header_b64)
        signature = _b64url_decode(signature_b64)
        signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError, UnicodeEncodeError):
        return None

    if not isinstance(header, dict):
        return None
    # Pin the algorithm: never take it from the token's own header choice.
    if header.get("alg") != "HS256":
        return None
    typ = header.get("typ")
    if typ is not None and (not isinstance(typ, str) or typ.upper() != "JWT"):
        return None

    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return None

    try:
        payload = _json_segment(payload_b64)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    now = time.time()
    if "exp" in payload:
        exp = _numeric_claim(payload.get("exp"))
        if exp is None or now >= exp + _LEEWAY_SECONDS:
            return None
    if "nbf" in payload:
        nbf = _numeric_claim(payload.get("nbf"))
        if nbf is None or now < nbf - _LEEWAY_SECONDS:
            return None

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        return None
    return sub
