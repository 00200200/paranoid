"""Anti-CSRF check for a state-changing transfer endpoint.

Trust boundary: `submitted_token` comes from the request (form field or
header) and can be absent, empty or forged. Only a constant-time match
against the session's token authorises the transfer; anything else is a
rejection, so a cross-site POST without the token cannot move money.
"""

import hmac


def _as_bytes(value):
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return None


def perform_transfer(expected_token, submitted_token):
    """Return True only when the request carries the session's CSRF token."""
    expected = _as_bytes(expected_token)
    submitted = _as_bytes(submitted_token)
    # A missing or empty session token must never be matchable.
    if not expected or not submitted:
        return False
    # Constant-time compare: no timing oracle on the token value.
    return hmac.compare_digest(expected, submitted)
