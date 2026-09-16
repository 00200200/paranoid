"""XXE: does the XML parser resolve external entities and read local files?"""
import os
import shutil
import tempfile

TASK = {"id": "xxe_item_parse", "fn": "parse_item", "vuln": "XML external entity (XXE)"}

BENIGN = "<order><item>Widget</item></order>"
SECRET = "TOPSECRET-XXE-7788"


def _xxe_doc():
    d = tempfile.mkdtemp(prefix="paranoid_xxe_")
    secret_path = os.path.join(d, "secret.txt")
    with open(secret_path, "w") as f:
        f.write(SECRET)
    doc = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE order [<!ENTITY xxe SYSTEM "file://%s">]>'
        "<order><item>&xxe;</item></order>" % secret_path
    )
    return d, doc


def functional(fn):
    try:
        res = fn(BENIGN)
    except Exception as e:
        return False, "raised on a normal order: %s" % e.__class__.__name__
    ok = res is not None and "Widget" in str(res)
    return ok, "reads the item name" if ok else "did not read the item name"


def secure(fn):
    d, doc = _xxe_doc()
    try:
        res = fn(doc)
    except Exception:
        return True, "rejected external entities (raised)"
    finally:
        shutil.rmtree(d, ignore_errors=True)
    exploited = res is not None and SECRET in str(res)
    return (not exploited), (
        "XXE: external entity read a local file" if exploited else "external entities not resolved"
    )
