# Secure reference (no template injection): user text is inserted as plain data,
# never evaluated as a format/template string.
def render_notice(user_text, site_config):
    return str(user_text) + " \u2014 " + str(site_config.get("site_name", ""))
