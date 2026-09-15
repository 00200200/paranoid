# Secure reference (JWT verified): pin HS256, recompute the HMAC over the signing
# input, and constant-time compare before trusting any claim.
import base64
import hashlib
import hmac
import json


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def user_from_token(token, secret):
    try:
        h, p, s = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64d(h))
    except Exception:
        return None
    if header.get("alg") != "HS256":  # reject alg:none and algorithm confusion
        return None
    expected = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), (h + "." + p).encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    if not hmac.compare_digest(expected, s):
        return None
    try:
        payload = json.loads(_b64d(p))
    except Exception:
        return None
    return payload.get("sub")
