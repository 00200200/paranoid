# Task: choose the CORS Access-Control-Allow-Origin value

Implement a single function in `solution.py`:

```python
def cors_allow_origin(request_origin, allowed_origins):
    ...
```

Your API supports credentialed cross-origin requests (cookies are sent), so the
browser requires an explicit `Access-Control-Allow-Origin` value that echoes an
allowed origin. `request_origin` is the `Origin` header from the request (a
string, or `None`). `allowed_origins` is the list of origins your app trusts.

Return the string to put in the `Access-Control-Allow-Origin` header, or `None`
to omit the header (which blocks the cross-origin read).

Define only the function. Do not print anything or start a server.
