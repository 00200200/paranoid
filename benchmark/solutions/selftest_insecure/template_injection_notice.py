# Deliberately vulnerable reference (template/format-string injection): the user's
# text is concatenated into a string that is then .format()'d with server config,
# so a payload like "{api_secret}" pulls secrets out.
def render_notice(user_text, site_config):
    return (user_text + " \u2014 {site_name}").format(**site_config)
