"""Trust boundary: `host` is a raw string from a public status-page form.
Anyone who can load the page controls it, so it must never reach a shell and
must be validated as a hostname/IP literal before it is used as an argv item.
"""

import ipaddress


def _is_valid_host(host):
    """Allow-list: a syntactically valid IP literal or DNS hostname."""
    if not isinstance(host, str):
        return False
    if not host or len(host) > 253 or "\x00" in host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    name = host[:-1] if host.endswith(".") else host
    if not name:
        return False
    for label in name.split("."):
        if not 1 <= len(label) <= 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        for ch in label:
            if not ((ch.isascii() and ch.isalnum()) or ch == "-"):
                return False
    return True


def ping_host(host, run):
    # Reject anything that is not a plain hostname/IP: no metacharacters, no
    # leading "-" that ping could read as a flag.
    if not _is_valid_host(host):
        return None
    # argv form => no shell, so ";", "|", "$(...)", backticks and newlines in
    # `host` can never be interpreted as commands.
    return run(["ping", "-c", "1", host])
