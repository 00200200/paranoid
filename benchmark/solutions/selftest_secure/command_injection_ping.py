# Secure reference (command injection blocked): no shell, host is one argv token.
def ping_host(host, run):
    return run(["ping", "-c", "1", host])
