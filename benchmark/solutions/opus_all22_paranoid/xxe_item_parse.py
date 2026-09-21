"""Trust boundary: `xml_text` is a request body from any API client. XML parsers
will happily read local files and make network calls through external entities,
and expand nested internal entities into gigabytes (billion laughs). A legitimate
order needs no DTD at all, so any doctype/entity declaration is refused outright
and the body is size-bounded before parsing.
"""

import xml.etree.ElementTree as ET

_MAX_XML = 1 << 20  # 1 MiB


def parse_item(xml_text):
    if isinstance(xml_text, (bytes, bytearray)):
        raw = bytes(xml_text)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    elif isinstance(xml_text, str):
        text = xml_text
    else:
        return None

    if not text.strip() or len(text) > _MAX_XML:
        return None

    # No DTD => no external entity (file:///etc/passwd, http://169.254.169.254)
    # and no entity-expansion bomb. ElementTree never fetches external entities,
    # but it does expand internal ones, so this check is what stops both.
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered or "<!notation" in lowered:
        return None

    try:
        root = ET.fromstring(text)
    except ValueError:
        try:  # str carrying an encoding declaration
            root = ET.fromstring(text.encode("utf-8"))
        except (ET.ParseError, ValueError):
            return None
    except ET.ParseError:
        return None

    if root.tag == "item":
        return root.text
    item = root.find(".//item")
    if item is None:
        return None
    return item.text
