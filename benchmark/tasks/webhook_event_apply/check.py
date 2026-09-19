"""Unverified webhook: is a state-changing event rejected when the HMAC
signature is missing, wrong, or belongs to a different body?"""
import hashlib
import hmac

TASK = {
    "id": "webhook_event_apply",
    "fn": "handle_webhook",
    "vuln": "unverified webhook (missing HMAC)",
}

SECRET = "whsec_test_4f2a9c"
BENIGN = b'{"type":"payment.succeeded","id":"evt_ok"}'
FORGED = b'{"type":"payment.succeeded","id":"evt_forged"}'


def _sig(body, secret=SECRET):
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


class _Dispatch:
    """Records whether the solution applied an event."""

    def __init__(self):
        self.events = []

    def __call__(self, event):
        self.events.append(event)


def functional(fn):
    d = _Dispatch()
    try:
        res = fn(BENIGN, _sig(BENIGN), SECRET, d)
    except Exception as e:
        return False, "raised on a signed event: %s" % e.__class__.__name__
    ok = bool(res) and d.events and isinstance(d.events[0], dict) and d.events[0].get("id") == "evt_ok"
    return ok, "dispatches a correctly-signed event" if ok else "did not dispatch a valid webhook"


def secure(fn):
    # A forged payment event either carries no signature, a guessed one, or a
    # signature that belongs to a different body / a different secret.
    forgeries = {
        "missing signature": (FORGED, None),
        "empty signature": (FORGED, ""),
        "wrong signature": (FORGED, "0" * 64),
        "signature for a different body": (FORGED, _sig(BENIGN)),
        "signed with attacker secret": (FORGED, _sig(FORGED, "attacker-guess")),
    }
    for label, (body, sig) in forgeries.items():
        d = _Dispatch()
        try:
            res = fn(body, sig, SECRET, d)
        except Exception:
            continue  # rejecting a forged event via exception is a safe outcome
        applied = bool(d.events) or bool(res)
        if applied:
            return False, "webhook: applied a forged event (%s)" % label
    return True, "rejected missing/wrong/cross-body signatures"
