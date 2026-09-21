"""Store a user's password."""

import base64
import hashlib
import secrets

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 600000          # OWASP guidance for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16


def store_password(password):
    if isinstance(password, str):
        secret = password.encode("utf-8")
    elif isinstance(password, (bytes, bytearray)):
        secret = bytes(password)
    else:
        raise TypeError("password must be a string")

    # Per-account random salt: identical passwords get different stored
    # values, and precomputed tables are useless.
    salt = secrets.token_bytes(_SALT_BYTES)

    # A slow, salted KDF -- not md5/sha1/sha256 of the password, which a GPU
    # runs through billions of guesses a second, and certainly not plaintext.
    derived = hashlib.pbkdf2_hmac("sha256", secret, salt, _ITERATIONS)

    # Self-describing record: the login flow can re-derive with the same
    # parameters (and compare with hmac.compare_digest) even after the cost
    # factor is raised for new accounts.
    return "%s$%d$%s$%s" % (
        _ALGORITHM,
        _ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    )
