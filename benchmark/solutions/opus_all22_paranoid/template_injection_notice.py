"""Trust boundary: `user_text` is raw user input and `site_config` holds server
secrets. The user's string is treated strictly as *data* -- it is never used as
a format string or template source, so "{site_config[api_secret]}" / "{{ 7*7 }}"
is echoed back literally instead of being evaluated against the config.
"""

_SEPARATOR = " — "  # " - " with an em dash
_MAX_TEXT = 4096


def _as_text(value):
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def render_notice(user_text, site_config):
    text = _as_text(user_text)
    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT]

    site_name = ""
    if isinstance(site_config, dict):
        site_name = _as_text(site_config.get("site_name", ""))

    # Plain concatenation: no .format(), no f-string over user input, no
    # Template/Jinja render, so no server-side template injection and no path
    # from user text to any other key in site_config.
    return text + _SEPARATOR + site_name
