"""Read one note out of the user's own notes directory.

Trust boundary: `name` is typed by the user, so it may contain "..", a
leading "/", or a symlink pointing at /etc/passwd. The name must be a plain
filename, and the fully resolved path must still sit inside the resolved
base directory, which also defeats symlink escapes.
"""

import os


def read_note(base_dir, name):
    """Return the note's text, or None if it does not exist / is out of bounds."""
    if not isinstance(name, str) or not isinstance(base_dir, (str, os.PathLike)):
        return None
    if not name or "\x00" in name:
        return None
    # A note name is a bare filename: no separators, no traversal, not absolute.
    if "/" in name or "\\" in name or os.path.isabs(name):
        return None
    if name in (".", "..") or name != os.path.basename(name):
        return None

    try:
        base = os.path.realpath(base_dir)
        target = os.path.realpath(os.path.join(base, name))
    except (OSError, ValueError):
        return None

    # Containment check after resolution (catches symlinks out of the sandbox).
    if target != base and not target.startswith(base + os.sep):
        return None
    if not os.path.isfile(target):
        return None

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None
