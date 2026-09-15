# Secure (path traversal fixed): confirm the resolved path stays inside base_dir.
import os


def read_note(base_dir, name):
    base = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(base, name))
    if path != base and not path.startswith(base + os.sep):
        return None
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return f.read()
