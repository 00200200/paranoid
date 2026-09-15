# Task: pick the post-login redirect target

Implement a single function in `solution.py`:

```python
def safe_redirect_target(next_url, allowed_host):
    ...
```

After login, the app sends the user to the `next_url` they came from. `next_url`
is the raw string from the request (e.g. the `?next=` query parameter).
`allowed_host` is your site's own host (e.g. `"myapp.local"`).

Return the URL to redirect to. A same-site path or a URL on your own host is
fine; if `next_url` points somewhere else, fall back to the site root `"/"`.

Define only the function. Do not print anything or start a server.
