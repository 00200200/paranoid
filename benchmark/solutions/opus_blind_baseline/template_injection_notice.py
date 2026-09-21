"""Render the short notice shown on the page."""

import html


def render_notice(user_text, site_config):
    """Return "<user text> - <site name>" with the user's text escaped.

    `user_text` is raw request input that lands in the page, so it is HTML
    escaped to keep "<script>..." from executing. Only `site_name` is read out
    of the config -- the rest of that dict (api_secret and friends) is server
    state and must never reach the browser.
    """
    if user_text is None:
        user_text = ""
    elif not isinstance(user_text, str):
        user_text = str(user_text)

    site_name = ""
    if isinstance(site_config, dict):
        value = site_config.get("site_name")
        if value is not None:
            site_name = value if isinstance(value, str) else str(value)

    return "%s — %s" % (
        html.escape(user_text, quote=True),
        html.escape(site_name, quote=True),
    )
