# Secure reference (upload restricted): strip any path, require a last suffix
# on the image allow-list, and reject executable types hiding in earlier
# suffixes (Apache `file.php.png`) or before a semicolon (IIS `file.php;.jpg`).
import os

ALLOWED = {"jpg", "jpeg", "png", "gif", "webp"}
DANGEROUS = {"php", "phtml", "php5", "jsp", "asp", "aspx", "svg", "html", "htm", "js", "sh", "exe"}


def accept_upload(filename):
    if not filename:
        return None
    base = os.path.basename(filename)
    if not base or ".." in base or "/" in base or "\\" in base or ";" in base:
        return None
    if "." not in base:
        return None
    parts = [p for p in base.split(".") if p]
    if not parts or parts[-1].lower() not in ALLOWED:
        return None
    if any(p.lower() in DANGEROUS for p in parts):
        return None
    return base
