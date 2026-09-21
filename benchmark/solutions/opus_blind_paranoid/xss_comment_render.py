"""Render a user comment as HTML.

Trust boundary: `text` is whatever a commenter typed and the result is
inserted straight into the page, so this is the textbook stored-XSS sink.
The text is HTML-escaped (including quotes) before it is wrapped, so
<script>, <img onerror=...> and attribute-breakout payloads render as text.
"""

import html


def render_comment(text):
    """Return the comment wrapped in a div, with the text escaped."""
    if text is None:
        raw = ""
    elif isinstance(text, str):
        raw = text
    else:
        raw = str(text)

    return '<div class="comment">' + html.escape(raw, quote=True) + "</div>"
