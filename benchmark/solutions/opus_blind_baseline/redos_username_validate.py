"""Validate a signup username."""

import re

# Explicit ASCII ranges. str.isalnum() would accept non-ASCII letters and digits
# such as "admın" or "١٢٣", which invites homograph and normalization abuse.
# \Z (not $) so a trailing newline cannot sneak through.
_USERNAME_RE = re.compile(r"\A[A-Za-z0-9]+\Z")


def is_valid_username(value):
    """Return True if `value` is a non-empty ASCII alphanumeric string."""
    if not isinstance(value, str):
        return False
    return _USERNAME_RE.match(value) is not None
