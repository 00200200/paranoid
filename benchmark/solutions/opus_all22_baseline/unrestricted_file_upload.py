"""Accept an uploaded avatar file."""

import re

# Image types only, and none that can carry script (no .svg, no .html).
_ALLOWED_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "webp"})

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_-]+")

_MAX_STEM = 64


def accept_upload(filename):
    if not isinstance(filename, str):
        return None

    name = filename.strip()
    if not name:
        return None

    # Null bytes and control characters truncate names in lower layers
    # ("avatar.png\x00.php").
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return None

    # Keep only the final component, so "../../etc/cron.d/x" or a Windows
    # path can never steer where the file is written.
    name = name.replace("\\", "/").split("/")[-1]
    if name in ("", ".", ".."):
        return None

    stem, dot, extension = name.rpartition(".")
    if not dot:
        return None

    extension = extension.lower()
    if extension not in _ALLOWED_EXTENSIONS:
        return None

    # Rewrite the stem: one dot remains in the stored name, so a double
    # extension ("shell.php.png") cannot be re-interpreted by the server, and
    # no separator or wildcard survives.
    stem = _UNSAFE_CHARS.sub("_", stem).strip("_-")
    if not stem:
        return None

    return stem[:_MAX_STEM] + "." + extension
