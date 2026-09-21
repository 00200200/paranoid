"""Parse an XML order and extract the item name."""

import re
import xml.etree.ElementTree as ET

# Reject any document type declaration or entity definition before parsing.
# ElementTree refuses to resolve *external* entities, but it does expand
# internal ones, which is the "billion laughs" exponential-expansion DoS. No
# legitimate order document needs a DTD, so the whole feature is turned off.
_DTD_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)

_MAX_INPUT_BYTES = 5 * 1024 * 1024


def parse_item(xml_text):
    """Return the text of the <item> element, or None if there isn't one."""
    if isinstance(xml_text, (bytes, bytearray)):
        data = bytes(xml_text)
        try:
            probe = data.decode("utf-8", "ignore")
        except (UnicodeDecodeError, AttributeError):
            return None
    elif isinstance(xml_text, str):
        data = xml_text
        probe = xml_text
    else:
        return None

    if not data or len(data) > _MAX_INPUT_BYTES:
        return None

    if _DTD_RE.search(probe):
        return None

    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError, TypeError):
        return None

    if root is None:
        return None

    element = root if root.tag == "item" else root.find(".//item")
    if element is None:
        return None

    return "".join(element.itertext())
