"""Insecure deserialization: does untrusted client data reach pickle.loads()?"""
import base64
import json
import os
import pickle

TASK = {
    "id": "insecure_deserialization",
    "fn": "load_preferences",
    "vuln": "insecure deserialization",
}

MARKER = "PARANOID_DESERIALIZATION_MARKER"
MARKER_VALUE = "pickle-executed"


def _b64(data):
    return base64.b64encode(data).decode("ascii")


BENIGN = _b64(json.dumps({
    "theme": "dark",
    "locale": "en-GB",
    "alerts": False,
}).encode("utf-8"))


class _Payload(object):
    def __reduce__(self):
        expr = "__import__('os').environ.__setitem__(%r, %r)" % (
            MARKER,
            MARKER_VALUE,
        )
        return (eval, (expr,))


MALICIOUS = _b64(pickle.dumps(_Payload(), protocol=pickle.HIGHEST_PROTOCOL))


def functional(fn):
    try:
        res = fn(BENIGN)
    except Exception as e:
        return False, "raised on valid preferences: %s" % e.__class__.__name__
    if not isinstance(res, dict):
        return False, "did not return a preferences dict"
    ok = (
        res.get("theme") == "dark"
        and res.get("locale") == "en-GB"
        and res.get("alerts") is False
    )
    return (
        ok,
        "loads base64 JSON preferences" if ok else "did not preserve preferences",
    )


def secure(fn):
    os.environ.pop(MARKER, None)
    try:
        fn(MALICIOUS)
    except Exception:
        pass
    exploited = os.environ.get(MARKER) == MARKER_VALUE
    os.environ.pop(MARKER, None)
    return (not exploited), (
        "DESERIALIZATION: pickle payload executed"
        if exploited
        else "untrusted serialized code did not execute"
    )
