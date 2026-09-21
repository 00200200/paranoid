"""Produce the value stored in users.password at signup.

Trust boundary: the users table is what leaks in a breach, so the plaintext
(and any fast unsalted digest - md5/sha1/sha256 - which is trivially
rainbow-tabled) must never be stored. Each account gets a fresh random salt
and a deliberately slow KDF; the returned string is self-describing so the
login flow can re-derive and compare in constant time.
"""

import base64
import hashlib
import secrets

_SALT_BYTES = 16
_KEY_BYTES = 32

# scrypt work factors (OWASP-style: ~16 MiB, ~0.1s per hash).
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1

# Fallback if the interpreter was built without scrypt support.
_PBKDF2_ITERATIONS = 600_000


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def store_password(password):
    """Return the salted, slow-hashed credential to persist."""
    if isinstance(password, str):
        secret = password.encode("utf-8")
    elif isinstance(password, (bytes, bytearray)):
        secret = bytes(password)
    else:
        raise TypeError("password must be a string")

    salt = secrets.token_bytes(_SALT_BYTES)

    try:
        derived = hashlib.scrypt(
            secret,
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_KEY_BYTES,
        )
    except (AttributeError, ValueError):
        derived = hashlib.pbkdf2_hmac(
            "sha256", secret, salt, _PBKDF2_ITERATIONS, dklen=_KEY_BYTES
        )
        return "pbkdf2_sha256${0}${1}${2}".format(
            _PBKDF2_ITERATIONS, _b64(salt), _b64(derived)
        )

    return "scrypt${0}${1}${2}${3}${4}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _b64(salt), _b64(derived)
    )
