"""Identify the caller from an HS256 JSON Web Token."""

import base64
import binascii
import hashlib
import hmac
import json
import time


def _b64url_decode(segment):
    try:
        data = segment.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        return None
    data += b"=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data)
    except (binascii.Error, ValueError):
        return None


def _json_segment(segment):
    raw = _b64url_decode(segment)
    if raw is None:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _numeric(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def user_from_token(token, secret):
    if not isinstance(token, str) or not token:
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64 or not signature_b64:
        return None

    header = _json_segment(header_b64)
    if header is None:
        return None

    # The algorithm is decided by this server, not by the token. Accepting the
    # header's choice is what makes "alg": "none" and RS256->HS256 confusion
    # work; anything that is not our HS256 is rejected outright.
    if header.get("alg") != "HS256":
        return None

    if isinstance(secret, str):
        key = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray)):
        key = bytes(secret)
    else:
        return None
    if not key:
        return None

    signature = _b64url_decode(signature_b64)
    if signature is None:
        return None

    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return None

    payload = _json_segment(payload_b64)
    if payload is None:
        return None

    now = time.time()
    exp = _numeric(payload.get("exp"))
    if exp is not None and now >= exp:
        return None
    nbf = _numeric(payload.get("nbf"))
    if nbf is not None and now < nbf:
        return None

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        return None
    return sub
