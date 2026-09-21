"""Trust boundary: the whole JWT is attacker-supplied. The header is data, not
policy: the algorithm is pinned to HS256 server-side (so "alg":"none" and an
RS256->HS256 confusion are impossible), the signature is verified in constant
time, and only then is any claim believed.
"""

import base64
import binascii
import hashlib
import hmac
import json
import time

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_MAX_TOKEN = 8192
_LEEWAY = 60  # seconds of clock skew


def _b64url_decode(segment):
    if not segment or any(ch not in _B64URL_ALPHABET for ch in segment):
        return None
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError):
        return None


def _json_object(raw):
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
    if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN:
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

    header = _json_object(_b64url_decode(header_b64))
    if header is None:
        return None
    # Algorithm is decided by the server, not by the token.
    if header.get("alg") != "HS256":
        return None
    typ = header.get("typ")
    if typ is not None and (not isinstance(typ, str) or typ.upper() != "JWT"):
        return None

    signature = _b64url_decode(signature_b64)
    if signature is None:
        return None
    expected = hmac.new(
        key, (header_b64 + "." + payload_b64).encode("ascii"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(signature, expected):
        return None

    payload = _json_object(_b64url_decode(payload_b64))
    if payload is None:
        return None

    now = time.time()
    if "exp" in payload:
        exp = _numeric(payload.get("exp"))
        if exp is None or now > exp + _LEEWAY:
            return None
    if "nbf" in payload:
        nbf = _numeric(payload.get("nbf"))
        if nbf is None or now + _LEEWAY < nbf:
            return None

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        return None
    return sub
