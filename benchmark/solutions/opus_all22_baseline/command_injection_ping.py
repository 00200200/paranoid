"""Ping a host for the status page."""

import ipaddress
import re

# One DNS label: starts and ends alphanumeric, hyphens allowed in between.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(r"\A" + _LABEL + r"(?:\." + _LABEL + r")*\.?\Z")


def _is_valid_host(host):
    """True for an IP literal or a syntactically valid DNS hostname."""
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return _HOSTNAME_RE.match(host) is not None


def ping_host(host, run):
    if not isinstance(host, str):
        return None

    candidate = host.strip()
    if not _is_valid_host(candidate):
        # Anything with shell metacharacters, spaces, quotes or a leading "-"
        # fails this check, so it never reaches the command line at all.
        return None

    # argv form: the program is executed directly, with no shell to interpret
    # metacharacters, and the host is a single argument that cannot be split.
    return run(["ping", "-c", "1", candidate])
