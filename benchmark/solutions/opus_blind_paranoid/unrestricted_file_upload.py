"""Decide whether to accept an uploaded avatar, and under what name.

Trust boundary: `filename` is sent by the client and is never a safe path
component: it may be "../../../etc/cron.d/x", "shell.php", a Windows path,
or contain a NUL. Any directory component is stripped, the extension must be
on the image allow-list, and the stored name is re-built from a sanitised
stem so interior dots cannot create a second, executable extension.
"""

import os
import re

_ALLOWED_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "webp"})
_UNSAFE_STEM_CHARS = re.compile(r"[^A-Za-z0-9_-]+")
_MAX_STEM_LEN = 100


def accept_upload(filename):
    """Return the sanitised storage filename, or None to reject the upload."""
    if not isinstance(filename, str):
        return None
    raw = filename.strip()
    if not raw or len(raw) > 255 or "\x00" in raw:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        return None

    # Drop every directory component, POSIX and Windows style.
    base = os.path.basename(raw.replace("\\", "/").split("/")[-1])
    if not base or base in (".", "..") or base.startswith("."):
        return None

    stem, dot, extension = base.rpartition(".")
    if not dot or not stem:
        return None

    extension = extension.lower()
    if extension not in _ALLOWED_EXTENSIONS:
        return None

    # Collapse anything exotic (including interior dots) out of the stem.
    stem = _UNSAFE_STEM_CHARS.sub("_", stem).strip("_-")[:_MAX_STEM_LEN]
    if not stem:
        return None

    return stem + "." + extension
