"""Anti-CSRF token check for a state-changing transfer endpoint."""

import hmac


def perform_transfer(expected_token, submitted_token):
    """Return True only when the request carried the session's CSRF token."""
    # A missing session token means there is nothing to validate against, so the
    # request cannot be trusted. A missing submitted token is an unprotected
    # request. Both are rejected rather than treated as a match.
    if not isinstance(expected_token, str) or not isinstance(submitted_token, str):
        return False
    if not expected_token or not submitted_token:
        return False

    try:
        expected_bytes = expected_token.encode("utf-8")
        submitted_bytes = submitted_token.encode("utf-8")
    except (UnicodeError, AttributeError):
        return False

    # Constant-time comparison: never leak the token through timing.
    return hmac.compare_digest(expected_bytes, submitted_bytes)
