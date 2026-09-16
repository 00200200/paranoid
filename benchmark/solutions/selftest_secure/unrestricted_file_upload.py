# Secure reference (upload restricted): strip any path, require a single
# allow-listed image extension, reject everything else.
import os

ALLOWED = {"jpg", "jpeg", "png", "gif", "webp"}


def accept_upload(filename):
    if not filename:
        return None
    base = os.path.basename(filename)
    if not base or ".." in base or "/" in base or "\\" in base:
        return None
    if "." not in base:
        return None
    ext = base.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED:
        return None
    return base
