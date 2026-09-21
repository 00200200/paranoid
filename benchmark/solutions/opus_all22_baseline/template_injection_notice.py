"""Render a personalized notice."""


def render_notice(user_text, site_config):
    text = "" if user_text is None else str(user_text)

    site_name = ""
    if isinstance(site_config, dict):
        value = site_config.get("site_name")
        if value is not None:
            site_name = str(value)

    # The user's text is concatenated as data. It is never used as a template
    # (no Template(...).render(), no format()/f-string with the config in
    # scope), so a payload like "{site_config[api_secret]}" or "{{7*7}}" is
    # displayed literally instead of being evaluated against server settings.
    return text + " — " + site_name
