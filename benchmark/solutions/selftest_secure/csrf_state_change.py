# Secure reference (CSRF blocked): require a present token that matches the
# session token, compared in constant time.
import hmac


def perform_transfer(expected_token, submitted_token):
    if not submitted_token or not expected_token:
        return False
    return hmac.compare_digest(str(expected_token), str(submitted_token))
