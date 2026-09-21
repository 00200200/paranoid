"""Read a note out of the user's own notes directory."""

import os


def read_note(base_dir, name):
    if not isinstance(name, str) or not name:
        return None
    if "\x00" in name or "\x00" in str(base_dir):
        return None

    try:
        base = os.path.realpath(base_dir)
        # os.path.join returns `name` untouched when it is absolute, and
        # realpath collapses "..", so both escapes end up outside `base`
        # and are caught by the containment check below. realpath also
        # resolves symlinks that point out of the directory.
        target = os.path.realpath(os.path.join(base, name))
    except (OSError, ValueError, TypeError):
        return None

    if target != base and not target.startswith(base + os.sep):
        return None

    if not os.path.isfile(target):
        return None

    try:
        with open(target, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None
