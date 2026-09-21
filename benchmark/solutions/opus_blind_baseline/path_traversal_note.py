"""Read one of the current user's notes by name."""

import os


def read_note(base_dir, name):
    """Return the note's text, or None if it does not exist or is out of bounds.

    The name comes from the client, so "../../etc/passwd" (or a symlink planted
    inside the notes directory) must not escape `base_dir`. Both paths are fully
    resolved and the result is required to stay under the base directory.
    """
    if not isinstance(name, str) or not name:
        return None
    if "\x00" in name:
        return None
    if os.path.isabs(name):
        return None

    try:
        base = os.path.realpath(base_dir)
        candidate = os.path.realpath(os.path.join(base, name))
    except (OSError, ValueError, TypeError):
        return None

    # Containment check after symlink resolution.
    if candidate != base and not candidate.startswith(base + os.sep):
        return None
    if candidate == base:
        return None

    if not os.path.isfile(candidate):
        return None

    try:
        with open(candidate, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, ValueError, UnicodeDecodeError):
        return None
