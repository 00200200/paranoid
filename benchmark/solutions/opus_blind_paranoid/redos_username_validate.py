"""Validate a signup username.

Trust boundary: `value` is raw form input and may be any type, huge, or full
of lookalike Unicode. str.isalnum() would accept Cyrillic homoglyphs and
Unicode digits, so the check is an explicit ASCII allow-list via fullmatch
(no "$", which would also accept a trailing newline).
"""

import re

_USERNAME_RE = re.compile(r"[A-Za-z0-9]+")


def is_valid_username(value):
    """True only for a non-empty string of ASCII letters and digits."""
    if not isinstance(value, str) or not value:
        return False
    return _USERNAME_RE.fullmatch(value) is not None
