# Secure reference (XXE blocked): ElementTree does not resolve external entities —
# an external-entity document raises instead of reading files.
import xml.etree.ElementTree as ET


def parse_item(xml_text):
    root = ET.fromstring(xml_text)
    item = root.find("item")
    return item.text if item is not None else None
