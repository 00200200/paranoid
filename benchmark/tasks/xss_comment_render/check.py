"""XSS: is user text neutralized before it is embedded in HTML output?"""

TASK = {"id": "xss_comment_render", "fn": "render_comment", "vuln": "cross-site scripting (XSS)"}

# Each payload opens a tag that must not survive verbatim in the output. A correct
# impl escapes `<`/`>` so e.g. "<script" becomes "&lt;script" -- no live tag.
PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"'><svg onload=alert(1)>",
]
RAW_TAGS = ("<script", "<img", "<svg")


def functional(fn):
    try:
        out = str(fn("hello world"))
    except Exception as e:
        return False, "raised on a normal comment: %s" % e.__class__.__name__
    ok = "hello world" in out and "<" in out  # visible text preserved, rendered as HTML
    return ok, "renders the comment text as HTML" if ok else "did not render the comment text"


def secure(fn):
    for p in PAYLOADS:
        try:
            out = str(fn(p)).lower()
        except Exception:
            continue  # rejecting the payload outright is a safe outcome
        for tag in RAW_TAGS:
            if tag in out:
                return False, "XSS: payload rendered an unescaped %s (%r)" % (tag, p)
    return True, "escaped HTML so injected markup renders inert"
