import os


def read_note(base_dir, name):
    # Trust boundary: `name` is submitted from the app and fully
    # attacker-controlled, so it may contain "../" segments, an absolute path,
    # or point through a symlink that escapes the notes directory.
    # Defense: fully resolve the requested path and confirm it stays inside the
    # resolved base_dir before opening it. Any escape, or a missing file,
    # returns None.
    if not name or not isinstance(name, str):
        return None

    base = os.path.realpath(base_dir)
    candidate = os.path.realpath(os.path.join(base, name))

    # The resolved target must be base_dir itself's descendant. Comparing
    # against base + os.sep also rejects sibling dirs like "<base>_evil".
    if candidate != base and not candidate.startswith(base + os.sep):
        return None

    if not os.path.isfile(candidate):
        return None

    try:
        with open(candidate, "r") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None
