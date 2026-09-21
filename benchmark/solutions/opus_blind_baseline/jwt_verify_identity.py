"""Authenticate a caller from an HS256 JSON Web Token."""

import base64
import binascii
import hashlib
import hmac
import json
import time

_LEEWAY_SECONDS = 60


def _b64url_decode(segment):
    """Decode a base64url segment, restoring the stripped padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def user_from_token(token, secret):
    """Return the `sub` claim of a validly signed token, else None."""
    if not isinstance(token, str) or not token:
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
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        signature = _b64url_decode(signature_b64)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None

    # Pin the algorithm to HS256. Trusting the token's own `alg` would let a
    # caller present alg="none" (no signature) or swap in an asymmetric
    # algorithm and sign with the public key.
    if header.get("alg") != "HS256":
        return None

    signing_input = (header_b64 + "." + payload_b64).encode("ascii", "strict")
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return None

    now = time.time()
    exp = payload.get("exp")
    if exp is not None:
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            return None
        if now > exp + _LEEWAY_SECONDS:
            return None
    nbf = payload.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)) or isinstance(nbf, bool):
            return None
        if now + _LEEWAY_SECONDS < nbf:
            return None

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        return None
    return sub
