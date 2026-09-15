# Deliberately vulnerable reference (broken JWT auth): decodes the payload without
# ever verifying the signature, so any forged/unsigned token is trusted.
import base64
import json


def user_from_token(token, secret):
    parts = token.split(".")
    p = parts[1]
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    return payload.get("sub")
