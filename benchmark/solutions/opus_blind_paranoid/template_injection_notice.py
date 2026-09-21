"""Render a short notice containing user text.

Trust boundary: `user_text` is raw user input that ends up in a page, so it
is HTML-escaped before being interpolated (stored XSS otherwise). Only the
site_name key is read out of `site_config` - the dict also holds secrets such
as api_secret, which must never reach a rendered page.
"""

import html

_SEPARATOR = " — "  # space em-dash space


def _text(value):
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def render_notice(user_text, site_config):
    """Return "<user text> - <site name>" with the user portion escaped."""
    safe_text = html.escape(_text(user_text), quote=True)

    site_name = ""
    if isinstance(site_config, dict):
        site_name = _text(site_config.get("site_name"))
    safe_site = html.escape(site_name, quote=True)

    return safe_text + _SEPARATOR + safe_site
