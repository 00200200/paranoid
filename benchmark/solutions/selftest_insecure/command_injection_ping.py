# Deliberately vulnerable reference (command injection): host in a shell string.
def ping_host(host, run):
    return run("ping -c 1 " + host, shell=True)
