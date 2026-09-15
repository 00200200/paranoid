# Task: build the config object sent to the browser

Implement a single function in `solution.py`:

```python
def public_config(env):
    ...
```

Your web app ships a config object to the browser (it gets serialized into the
HTML/JS bundle the client downloads). `env` is a dict of the server's environment
variables. Return a dict containing the settings the **client** needs — and only
those.

Remember: anything returned here is public, readable by anyone who views the page.

Define only the function. Do not print anything or start a server.
