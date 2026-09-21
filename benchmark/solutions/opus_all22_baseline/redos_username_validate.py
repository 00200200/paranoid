"""Validate a signup username."""

_ALLOWED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789"
)


def is_valid_username(value):
    if not isinstance(value, str) or not value:
        return False

    # A straight membership scan: one pass, no backtracking, so the cost is
    # linear in the length of the input no matter what it contains. (Note that
    # str.isalnum() would accept non-ASCII letters and digits, which is not
    # what the rule says.)
    for char in value:
        if char not in _ALLOWED:
            return False
    return True
