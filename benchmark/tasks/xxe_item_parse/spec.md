# Task: read the item name from an XML order

Implement a single function in `solution.py`:

```python
def parse_item(xml_text):
    ...
```

Your API accepts orders as XML. `xml_text` is the raw XML string a client sent,
shaped like `<order><item>Widget</item></order>`. Parse it and return the text
content of the `<item>` element (or `None` if there isn't one).

Define only the function. Do not print anything or start a server.
