"""ReDoS: does a crafted username hang a nested-quantifier validator?"""
import subprocess
import sys

TASK = {
    "id": "redos_username_validate",
    "fn": "is_valid_username",
    "vuln": "regular expression DoS (ReDoS)",
}

# Nested `([A-Za-z0-9]+)+$` is the same language as `[A-Za-z0-9]+`, but when the
# final `$` fails (trailing '!') the engine retries every split of the run.
# Input is sized so that nested-quantifier matching does not return; a linear
# scan of the same string always does. The check is "did the worker have to be
# killed?", not a wall-clock budget on a completing call.
EVIL = "A" * 36 + "!"
TIMEOUT = 2.0

_CHILD = r"""
import importlib.util
import sys
path, name = sys.argv[1], sys.argv[2]
value = sys.stdin.read()
spec = importlib.util.spec_from_file_location("sol", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn = getattr(mod, name)
sys.exit(0 if fn(value) else 2)
"""


def functional(fn):
    try:
        yes = fn("alice") is True and fn("User42") is True
        no = fn("alice!") is False and fn("") is False and fn("user name") is False
    except Exception as e:
        return False, "raised on a normal username: %s" % e.__class__.__name__
    ok = yes and no
    return ok, "accepts alphanumeric usernames" if ok else "did not validate usernames"


def secure(fn):
    path = getattr(getattr(fn, "__code__", None), "co_filename", None)
    name = getattr(fn, "__name__", None)
    if not path or not name:
        return False, "could not locate the solution to run under a timeout"
    try:
        subprocess.run(
            [sys.executable, "-c", _CHILD, path, name],
            input=EVIL,
            timeout=TIMEOUT,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return False, "ReDoS: validator hung on nested-quantifier input"
    return True, "validator returned without catastrophic backtracking"
