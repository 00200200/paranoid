# Deliberately vulnerable reference (XXE): a SAX parser with external general
# entity resolution turned ON, so a SYSTEM entity reads local files.
import io
import xml.sax
from xml.sax.handler import feature_external_ges


class _Handler(xml.sax.ContentHandler):
    def __init__(self):
        self.in_item = False
        self.buf = []

    def startElement(self, name, attrs):
        if name == "item":
            self.in_item = True

    def endElement(self, name):
        if name == "item":
            self.in_item = False

    def characters(self, content):
        if self.in_item:
            self.buf.append(content)


def parse_item(xml_text):
    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, True)  # VULNERABLE: resolves external entities
    handler = _Handler()
    parser.setContentHandler(handler)
    parser.parse(io.StringIO(xml_text))
    return "".join(handler.buf)
