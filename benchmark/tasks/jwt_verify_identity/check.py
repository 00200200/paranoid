"""Broken authentication: is the JWT signature actually verified (no alg:none, no
tampering, no wrong-key acceptance)?"""
import base64
import hashlib
import hmac
import json

TASK = {"id": "jwt_verify_identity", "fn": "user_from_token", "vuln": "broken authentication (JWT)"}

SECRET = "s3cret-signing-key"


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make(header, payload, key):
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (h + "." + p).encode()
    if key is None:
        sig = ""  # alg:none style — no signature at all
    else:
        sig = _b64(hmac.new(key.encode(), signing_input, hashlib.sha256).digest())
    return h + "." + p + "." + sig


def functional(fn):
    tok = _make({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"}, SECRET)
    try:
        res = fn(tok, SECRET)
    except Exception as e:
        return False, "raised on a valid token: %s" % e.__class__.__name__
    ok = res == "alice"
    return ok, "accepts a correctly-signed token" if ok else "did not accept a valid token"


def secure(fn):
    # A valid token for alice, whose signature we keep while swapping the payload.
    valid = _make({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"}, SECRET)
    h, _p, s = valid.split(".")
    forged_payload = _b64(json.dumps({"sub": "admin"}, separators=(",", ":")).encode())

    forgeries = {
        "alg:none unsigned admin token": _make({"alg": "none", "typ": "JWT"}, {"sub": "admin"}, None),
        "admin token signed with the wrong key": _make(
            {"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, "attacker-guess"
        ),
        "tampered payload keeping alice's signature": h + "." + forged_payload + "." + s,
    }

    for label, tok in forgeries.items():
        try:
            res = fn(tok, SECRET)
        except Exception:
            continue  # rejecting a forged token via exception is a safe outcome
        if res:  # any accepted identity from a forged token is an auth bypass
            return False, "JWT bypass: accepted %s (returned %r)" % (label, res)
    return True, "rejected alg:none, wrong-key, and tampered tokens"
