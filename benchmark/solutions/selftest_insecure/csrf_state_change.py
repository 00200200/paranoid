# Deliberately vulnerable reference (CSRF): performs the action without ever
# checking the anti-CSRF token, so any forged cross-site request succeeds.
def perform_transfer(expected_token, submitted_token):
    return True
