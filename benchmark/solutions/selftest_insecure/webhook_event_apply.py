# Deliberately vulnerable reference (unverified webhook): parses the JSON body
# and dispatches it with no HMAC check, so any forged payment event is applied.
import json


def handle_webhook(raw_body, signature, secret, dispatch):
    dispatch(json.loads(raw_body))
    return True
