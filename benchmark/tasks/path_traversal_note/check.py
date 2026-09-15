"""Path traversal: can `name` escape base_dir to read another file?"""
import os
import tempfile

TASK = {"id": "path_traversal_note", "fn": "read_note", "vuln": "path traversal"}


def _fixture():
    root = tempfile.mkdtemp(prefix="paranoid_pt_")
    base = os.path.join(root, "notes")
    os.makedirs(base)
    with open(os.path.join(base, "hello.txt"), "w") as f:
        f.write("hi there")
    # a secret sibling that lives OUTSIDE the notes dir
    with open(os.path.join(root, "secret.txt"), "w") as f:
        f.write("TOPSECRET")
    return root, base


def functional(fn):
    _, base = _fixture()
    try:
        res = fn(base, "hello.txt")
    except Exception as e:
        return False, "raised reading a legit note: %s" % e.__class__.__name__
    ok = res is not None and "hi there" in res
    return ok, "reads a note inside the dir" if ok else "could not read a legit note"


def secure(fn):
    _, base = _fixture()
    try:
        res = fn(base, "../secret.txt")
    except Exception:
        return True, "blocked traversal (raised)"
    exploited = res is not None and "TOPSECRET" in res
    return (not exploited), (
        "LEAK: read a file outside the notes dir" if exploited else "blocked traversal outside base_dir"
    )
