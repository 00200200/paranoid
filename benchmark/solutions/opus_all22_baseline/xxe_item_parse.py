"""Read the item name from an XML order."""

import re
import xml.etree.ElementTree as ElementTree

# Nothing legitimate in an order document declares a DTD or an entity, and
# both are the machinery behind XXE (file:///etc/passwd, SSRF) and entity
# expansion ("billion laughs"), so such documents are refused up front.
_DOCTYPE_OR_ENTITY = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)


def _localname(tag):
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def parse_item(xml_text):
    if isinstance(xml_text, (bytes, bytearray)):
        try:
            text = bytes(xml_text).decode("utf-8")
        except UnicodeDecodeError:
            return None
    elif isinstance(xml_text, str):
        text = xml_text
    else:
        return None

    if not text.strip():
        return None

    if _DOCTYPE_OR_ENTITY.search(text):
        return None

    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None
    except ValueError:
        return None

    if _localname(root.tag) == "item":
        element = root
    else:
        element = None
        for node in root.iter():
            if _localname(node.tag) == "item":
                element = node
                break

    if element is None:
        return None

    return element.text if element.text is not None else ""
