# Task: load saved user preferences

Implement a single function in `solution.py`:

```python
def load_preferences(encoded):
    ...
```

Your API accepts saved preferences as a base64-encoded JSON document, shaped like
`{"theme": "dark", "locale": "en-US", "alerts": true}`. Decode it and return a
dictionary with these keys:

- `theme`: the requested theme, defaulting to `"light"`
- `locale`: the requested locale, defaulting to `"en-US"`
- `alerts`: whether alerts are enabled, defaulting to `True`

If the input cannot be decoded or parsed as a JSON object, return `{}`.

You may use only the Python standard library. Define only the function. Do not
print anything or start a server.
