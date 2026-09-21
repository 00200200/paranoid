"""Parse an order XML document and return the <item> text.

Trust boundary: `xml_text` is posted by a client, so the parser itself is the
attack surface - XXE (file:///etc/passwd, SSRF via SYSTEM entities) and
entity-expansion DoS (billion laughs). Entity declarations and external
entity references are rejected outright and parameter-entity parsing is
turned off, so neither class of payload can run.
"""

import xml.parsers.expat as _expat

_MAX_INPUT = 5 * 1024 * 1024


class _RejectedDoctype(Exception):
    """Raised when the document tries to declare or pull in an entity."""


def _local_name(tag):
    if "}" in tag:
        tag = tag.split("}", 1)[1]
    if ":" in tag:
        tag = tag.rsplit(":", 1)[1]
    return tag


def parse_item(xml_text):
    """Return the text of the first <item> element, or None."""
    if isinstance(xml_text, (bytes, bytearray)):
        data = bytes(xml_text)
    elif isinstance(xml_text, str):
        data = xml_text
    else:
        return None
    if not data or len(data) > _MAX_INPUT:
        return None

    state = {"depth": 0, "capture_depth": None, "chunks": [], "found": False}

    def start_element(name, _attrs):
        state["depth"] += 1
        if (
            not state["found"]
            and state["capture_depth"] is None
            and _local_name(name) == "item"
        ):
            state["capture_depth"] = state["depth"]
            state["chunks"] = []

    def character_data(chunk):
        if state["capture_depth"] is not None:
            state["chunks"].append(chunk)

    def end_element(_name):
        if state["capture_depth"] == state["depth"]:
            state["capture_depth"] = None
            state["found"] = True
        state["depth"] -= 1

    def reject(*_args, **_kwargs):
        raise _RejectedDoctype("entities are not allowed")

    parser = _expat.ParserCreate()
    try:
        # Never fetch or expand an external DTD / parameter entity.
        parser.SetParamEntityParsing(_expat.XML_PARAM_ENTITY_PARSING_NEVER)
    except (AttributeError, _expat.error):
        pass
    try:
        parser.buffer_text = True
    except AttributeError:
        pass

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = character_data
    parser.EntityDeclHandler = reject
    parser.UnparsedEntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject

    try:
        parser.Parse(data, True)
    except (_expat.ExpatError, _RejectedDoctype, UnicodeError, ValueError, TypeError):
        return None

    if not state["found"]:
        return None
    return "".join(state["chunks"])
