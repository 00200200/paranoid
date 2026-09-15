# Deliberately vulnerable reference (leaked secrets): dumps the whole environment
# into the client config, shipping secret keys to the browser.
def public_config(env):
    return dict(env)
