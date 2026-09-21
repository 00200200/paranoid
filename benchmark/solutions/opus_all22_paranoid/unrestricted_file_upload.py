"""Trust boundary: `filename` is whatever the client's multipart part claimed.
It can carry traversal ("../../var/www/shell.php"), a NUL, or an executable
extension. Only an image extension allow-list is accepted, the stored name is
rebuilt from a safe character set, and any path component is a hard reject.
"""

import os

_ALLOWED_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp"})
_MAX_FILENAME = 255
_MAX_STEM = 64


def accept_upload(filename):
    if not isinstance(filename, str):
        return None
    name = filename.strip()
    if not name or len(name) > _MAX_FILENAME:
        return None
    if "\x00" in name or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return None

    # No directory components, no drive letters / NTFS alternate data streams.
    separators = {"/", "\\", os.sep}
    if os.altsep:
        separators.add(os.altsep)
    if any(sep and sep in name for sep in separators):
        return None
    if ":" in name or ".." in name or name.startswith("."):
        return None

    stem, extension = os.path.splitext(name)
    extension = extension.lower()
    # Allow-list on the *final* extension, so "avatar.png.php" is rejected and
    # "avatar.php.png" cannot keep an executable component (see below).
    if extension not in _ALLOWED_EXTENSIONS or not stem:
        return None

    safe_stem = "".join(
        ch if (ch.isascii() and (ch.isalnum() or ch in "-_")) else "_"
        for ch in stem
    )
    safe_stem = safe_stem.strip("._-")[:_MAX_STEM]
    if not safe_stem:
        safe_stem = "upload"
    return safe_stem + extension
