# Deliberately vulnerable reference (open redirect): trusts next_url verbatim.
def safe_redirect_target(next_url, allowed_host):
    return next_url
