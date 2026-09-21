"""Authorize a state-changing request with an anti-CSRF token."""

import hmac


def perform_transfer(expected_token, submitted_token):
    # A session with no token, or a request that carried no token, can never
    # be authorized -- that is exactly the cross-site forged case.
    if not isinstance(expected_token, str) or not expected_token:
        return False
    if not isinstance(submitted_token, str) or not submitted_token:
        return False

    # Constant-time comparison so the token cannot be recovered byte by byte.
    try:
        return hmac.compare_digest(expected_token, submitted_token)
    except TypeError:
        # Non-ASCII strings: compare the encoded bytes instead.
        return hmac.compare_digest(
            expected_token.encode("utf-8"), submitted_token.encode("utf-8")
        )
