"""Render a user comment as HTML."""

import html


def render_comment(text):
    if text is None:
        comment = ""
    elif isinstance(text, str):
        comment = text
    else:
        comment = str(text)

    # Escape on output: <, >, &, " and ' become entities, so the comment is
    # shown as the characters the user typed instead of being parsed as markup
    # (or as an attribute break-out) when it lands in the page.
    return '<div class="comment">' + html.escape(comment, quote=True) + "</div>"
