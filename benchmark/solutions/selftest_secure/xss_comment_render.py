# Secure reference (XSS blocked): escape user text before embedding it in HTML.
import html


def render_comment(text):
    return "<div class='comment'>%s</div>" % html.escape(text)
