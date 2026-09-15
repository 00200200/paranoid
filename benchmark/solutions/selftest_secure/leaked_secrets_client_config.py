# Secure reference (no leaked secrets): allow-list what the client may see —
# explicitly-public vars and publishable keys only; never spread the whole env.
def public_config(env):
    out = {}
    for k, v in env.items():
        if k.startswith("PUBLIC_") or k.endswith("PUBLISHABLE_KEY"):
            out[k] = v
    return out
