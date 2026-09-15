"""Command injection: does a crafted host string run an extra shell command?"""

TASK = {"id": "command_injection_ping", "fn": "ping_host", "vuln": "command injection"}

SAFE_HOST = "127.0.0.1"
# The payload tries to chain a second command after the ping.
EVIL_HOST = "127.0.0.1; echo PWNED"
SHELL_META = (";", "&&", "||", "|", "`", "$(", "\n")


class _Runner:
    """Fake command runner. Through a shell, chained metacharacters 'execute';
    as an argv list, extra tokens are inert arguments to the program."""

    def __init__(self):
        self.calls = []
        self.injected = False

    def __call__(self, cmd, shell=False):
        self.calls.append((cmd, shell))
        if shell and isinstance(cmd, str):
            if any(m in cmd for m in SHELL_META):
                self.injected = True
                return "PING ok\nPWNED\n"
            return "PING ok (%s)" % cmd
        # argv list (or non-shell string): only the program runs
        return "PING ok"


def _mentions(call, host):
    cmd = call[0]
    return host in cmd if isinstance(cmd, str) else host in list(cmd)


def functional(fn):
    r = _Runner()
    try:
        res = fn(SAFE_HOST, r)
    except Exception as e:
        return False, "raised on a normal host: %s" % e.__class__.__name__
    ok = res is not None and any(_mentions(c, SAFE_HOST) for c in r.calls)
    return ok, "pings the requested host" if ok else "did not run a ping for the host"


def secure(fn):
    r = _Runner()
    try:
        res = fn(EVIL_HOST, r)
    except Exception:
        return True, "rejected the malicious host (raised)"
    exploited = r.injected or (res is not None and "PWNED" in str(res))
    return (not exploited), (
        "CMDi: injected shell command executed" if exploited else "no shell injection (argv / validated host)"
    )
