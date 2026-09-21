"""Trust boundary: `text` is a comment typed by one user and rendered into a
page read by every other user -- the classic stored-XSS path. The string is
escaped for HTML (including quotes) before it is placed in the markup, so
"<script>", "</div><img onerror=...>" and 'onmouseover="..."' render as text.
"""

import html


def render_comment(text):
    if text is None:
        value = ""
    elif isinstance(text, str):
        value = text
    else:
        value = str(text)

    # quote=True also escapes " and ', so the output stays safe even if it is
    # later interpolated into an attribute.
    return '<div class="comment">' + html.escape(value, quote=True) + "</div>"
