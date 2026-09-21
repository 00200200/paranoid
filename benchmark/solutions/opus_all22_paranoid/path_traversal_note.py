"""Trust boundary: `name` is a filename submitted by the user, so it may contain
"..", separators, an absolute path, a NUL, or point at a symlink. The name is
allow-listed to a single path component and the *resolved* path is then proved
to sit inside the resolved notes directory before anything is read.
"""

import os


def read_note(base_dir, name):
    if not isinstance(base_dir, str) or not isinstance(name, str):
        return None
    if not base_dir or not name:
        return None
    if "\x00" in base_dir or "\x00" in name:
        return None

    # One plain path component only: no traversal, no separators, no absolutes.
    separators = {"/", "\\", os.sep}
    if os.altsep:
        separators.add(os.altsep)
    if any(sep in name for sep in separators if sep):
        return None
    if name in (".", "..") or name.startswith("."):
        return None
    if os.path.isabs(name) or os.path.splitdrive(name)[0]:
        return None

    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, name))
    # realpath resolves symlinks, so a note symlinked to /etc/passwd fails here.
    if target != base and not target.startswith(base + os.sep):
        return None
    if not os.path.isfile(target):
        return None

    try:
        with open(target, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None
