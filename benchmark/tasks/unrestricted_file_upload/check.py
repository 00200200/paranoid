"""Unrestricted upload: is the stored filename allow-listed and path-sanitized?"""

TASK = {"id": "unrestricted_file_upload", "fn": "accept_upload", "vuln": "unrestricted file upload"}

GOOD = "photo.png"
# Each of these must NOT be stored with a dangerous type or a traversable path.
# Last-suffix-only checks miss Apache (file.php.png) and IIS (file.php;.jpg),
# where an executable type sits before the "image" extension.
EVIL = [
    "shell.php",
    "../../etc/passwd",
    "avatar.png.php",
    "logo.svg",
    "x.PhP",
    "app.jsp",
    "shell.php.png",
    "file.php;.jpg",
]
DANGEROUS_EXTS = {"php", "phtml", "php5", "jsp", "asp", "aspx", "svg", "html", "htm", "js", "sh", "exe"}


def _ext(name):
    return name.rsplit(".", 1)[1].lower() if "." in name else ""


def _tokens(name):
    # Split on '.' and ';' so php.png and php;.jpg both surface the php token.
    s = str(name).lower().replace("\\", "/").replace(";", ".")
    return [t for t in s.split(".") if t]


def functional(fn):
    try:
        res = fn(GOOD)
    except Exception as e:
        return False, "raised on a valid image: %s" % e.__class__.__name__
    ok = bool(res) and _ext(str(res)) in {"png", "jpg", "jpeg", "gif", "webp"} and ".." not in str(res)
    return ok, "accepts a legit image" if ok else "rejected a legit image upload"


def secure(fn):
    for name in EVIL:
        try:
            res = fn(name)
        except Exception:
            continue  # rejecting via exception is a safe outcome
        if not res:
            continue  # None / falsy = rejected = safe
        s = str(res)
        if "/" in s or "\\" in s or ".." in s:
            return False, "upload: stored a traversable path for %r" % name
        if any(t in DANGEROUS_EXTS for t in _tokens(s)):
            return False, "upload: accepted a dangerous type for %r" % name
    return True, "allow-listed extensions and sanitized the filename"
