# Secure reference (ReDoS blocked): linear scan of ASCII alphanumerics — same
# language as the nested-quantifier regex, without backtracking.
def is_valid_username(value):
    return isinstance(value, str) and value.isascii() and value.isalnum()
