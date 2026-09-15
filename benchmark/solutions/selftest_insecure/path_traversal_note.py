# Deliberately vulnerable (path traversal): joins the raw name onto base_dir.
import os


def read_note(base_dir, name):
    path = os.path.join(base_dir, name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()
