# Deliberately vulnerable reference (XSS): user text dropped straight into HTML.
def render_comment(text):
    return "<div class='comment'>%s</div>" % text
