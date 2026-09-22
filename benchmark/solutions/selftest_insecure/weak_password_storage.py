# Deliberately vulnerable reference (weak storage): unsalted MD5 of the
# password. Still one round-trip from a rainbow table; the login check that
# only rejects plaintext will score this as "safe".
import hashlib


def store_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()
