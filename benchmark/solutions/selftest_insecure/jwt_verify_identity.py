# Deliberately vulnerable reference (broken JWT auth): the "we blocked alg:none"
# half-fix. Rejects only the exact lowercase string "none", then trusts any
# empty-signature token — so alg "None" / "NONE" still forges admin.
import base64
import hashlib
import hmac
import json


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def user_from_token(token, secret):
    try:
        h, p, s = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64d(h))
        payload = json.loads(_b64d(p))
    except Exception:
        return None
    alg = header.get("alg")
    if alg == "none":
        return None
    if alg == "HS256":
        expected = _b64(hmac.new(secret.encode(), (h + "." + p).encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, s):
            return None
        return payload.get("sub")
    # Empty signature + any other alg spelling (None, NONE, …) accepted.
    if s == "":
        return payload.get("sub")
    return None
