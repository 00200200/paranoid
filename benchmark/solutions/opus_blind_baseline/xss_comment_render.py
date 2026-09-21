"""Render a user's comment as HTML."""

import html


def render_comment(text):
    """Return the comment wrapped in a div, with the user's text escaped.

    `text` is raw input that gets inserted into the page, so every HTML
    metacharacter is escaped. Interpolating it directly is stored XSS: one
    comment containing "<script>" would then run for every future reader.
    """
    if text is None:
        text = ""
    elif not isinstance(text, str):
        text = str(text)

    return '<div class="comment">%s</div>' % html.escape(text, quote=True)
