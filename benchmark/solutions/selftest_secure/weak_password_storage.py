# Secure reference (salted one-way hash): PBKDF2-HMAC-SHA256 with a random salt,
# stored as algo$iterations$salt$hash so login can verify without the plaintext.
import hashlib
import os


def store_password(password):
    salt = os.urandom(16)
    iterations = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), digest.hex())
