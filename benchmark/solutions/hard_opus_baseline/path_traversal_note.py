import os


def read_note(base_dir, name):
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, name))
    if target != base and not target.startswith(base + os.sep):
        return None
    if not os.path.isfile(target):
        return None
    try:
        with open(target, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return None
