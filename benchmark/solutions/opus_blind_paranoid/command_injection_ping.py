"""Reachability check for an operator status page.

Trust boundary: `host` is raw text from a web form, so it is attacker
controlled. It is never interpolated into a shell string; it is validated
against a hostname/IP pattern and handed to `run` as a single argv element
with no shell, so `; rm -rf /` or `$(curl evil)` cannot become a command.
"""

import ipaddress
import re

_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _is_valid_host(host):
    """True only for a syntactically valid IP literal or DNS hostname."""
    if not isinstance(host, str):
        return False
    host = host.strip()
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    name = host[:-1] if host.endswith(".") else host
    if not name:
        return False
    labels = name.split(".")
    return all(_LABEL_RE.match(label) for label in labels)


def ping_host(host, run):
    """Ping `host` once and return the command output (None if `host` is invalid)."""
    if not isinstance(host, str):
        return None
    host = host.strip()
    if not _is_valid_host(host):
        return None
    # argv form: no shell, and the validated host cannot start with '-' so it
    # can never be read as an option.
    return run(["ping", "-c", "1", host])
