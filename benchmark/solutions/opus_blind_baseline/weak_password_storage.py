"""Derive the value stored in users.password at signup."""

import base64
import hashlib
import os

# PBKDF2-HMAC-SHA256 with a per-user random salt. Storing the password itself
# (or a bare md5/sha1/sha256 of it) means one database leak exposes every
# account; a slow, salted KDF makes offline cracking and rainbow tables
# impractical. Iteration count follows the current OWASP guidance.
_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 600_000
_SALT_BYTES = 16


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def store_password(password):
    """Return the encoded hash to persist for this account."""
    if isinstance(password, str):
        secret = password.encode("utf-8")
    elif isinstance(password, (bytes, bytearray)):
        secret = bytes(password)
    else:
        raise TypeError("password must be a string")

    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", secret, salt, _ITERATIONS)

    # Self-describing format so the algorithm and cost can be upgraded later
    # without invalidating existing rows.
    return "%s$%d$%s$%s" % (_ALGORITHM, _ITERATIONS, _b64(salt), _b64(derived))
