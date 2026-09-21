"""Ping a host on behalf of an operator."""

import ipaddress
import re

# A hostname label: alphanumerics and hyphens, not starting/ending with a hyphen.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(r"\A%s(?:\.%s)*\.?\Z" % (_LABEL, _LABEL))


def _is_valid_host(host):
    """True if `host` is a plain hostname or IP literal (no shell metacharacters)."""
    if not isinstance(host, str):
        return False
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return _HOSTNAME_RE.match(host) is not None


def ping_host(host, run):
    """Ping `host` once and return the command output, or None for a bad host.

    The host is passed as a separate argv element with no shell involved, so a
    value such as "127.0.0.1; rm -rf /" can never be interpreted as a command.
    It is also validated against the hostname/IP grammar first, which keeps
    option-injection (a host starting with "-") out of the argument list.
    """
    if not _is_valid_host(host):
        return None
    return run(["ping", "-c", "1", host])
