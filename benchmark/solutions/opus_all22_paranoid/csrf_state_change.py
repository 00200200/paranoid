"""Trust boundary: a state-changing ("transfer funds") request. The submitted
token is fully attacker-controllable (it can be absent, empty, or guessed), so
it is only honoured when it matches the session token exactly, compared in
constant time.
"""

import hmac


def perform_transfer(expected_token, submitted_token):
    # A missing session token must never mean "no check required".
    if not isinstance(expected_token, str) or not expected_token:
        return False
    # Missing / non-string submitted token => reject (no CSRF token, no action).
    if not isinstance(submitted_token, str) or not submitted_token:
        return False
    # Constant-time compare: no timing oracle on the token value.
    return hmac.compare_digest(
        expected_token.encode("utf-8"), submitted_token.encode("utf-8")
    )
