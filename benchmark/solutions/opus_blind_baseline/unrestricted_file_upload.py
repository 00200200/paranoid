"""Decide whether to accept an uploaded avatar, and under what name."""

import os
import re

# Image types only, matched on the final extension. A deny-list ("reject .php")
# always misses something (.phtml, .php5, .svg with script, ...).
_ALLOWED_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp"})

_MAX_NAME_LENGTH = 100
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9_-]")


def accept_upload(filename):
    """Return the sanitized name to store the avatar under, or None to reject."""
    if not isinstance(filename, str) or not filename:
        return None
    if "\x00" in filename:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in filename):
        return None

    # Strip any directory component the client tried to smuggle in, handling
    # both separators so "..\\..\\windows\\x.png" is reduced as well.
    name = filename.replace("\\", "/").split("/")[-1]
    name = os.path.basename(name).strip()
    if not name or name in (".", ".."):
        return None

    stem, _, extension = name.rpartition(".")
    if not stem:
        # No extension at all, or a dotfile such as ".htaccess".
        return None

    extension = "." + extension.lower()
    if extension not in _ALLOWED_EXTENSIONS:
        return None

    # Collapse everything else in the stem: this removes inner dots, so a
    # double-extension name like "avatar.php.png" is stored as "avatar_php.png"
    # and can never be handed to a script handler.
    safe_stem = _UNSAFE_CHARS.sub("_", stem).strip("._-")
    if not safe_stem:
        return None
    safe_stem = safe_stem[:_MAX_NAME_LENGTH]

    return safe_stem + extension
