"""Trust boundary: this value lands in the users table, which is exactly what an
attacker walks away with after an SQL injection or a backup leak. So: never the
plaintext, never a bare/fast digest (md5/sha1/sha256), never a shared salt --
PBKDF2-HMAC-SHA256 with a fresh random salt and a high iteration count, stored
together with its parameters so they can be raised later.
"""

import base64
import hashlib
import secrets

_ALGORITHM = "pbkdf2_sha256"
_ITERATIONS = 600_000  # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16
_KEY_BYTES = 32


def store_password(password):
    if isinstance(password, str):
        secret = password.encode("utf-8")
    elif isinstance(password, (bytes, bytearray)):
        secret = bytes(password)
    else:
        raise TypeError("password must be a string")

    # Per-user random salt: identical passwords get different records, and
    # precomputed/rainbow tables are useless.
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", secret, salt, _ITERATIONS, _KEY_BYTES)

    return "{}${}${}${}".format(
        _ALGORITHM,
        _ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    )
