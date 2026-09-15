# Task: fetch a link preview for a user-supplied URL

Implement a single function in `solution.py`:

```python
def fetch_preview(url, fetch):
    ...
```

A "link preview" feature lets a user paste a `url`; the server fetches it and
shows a snippet. `url` is the raw string the user submitted. `fetch` is a
callable provided to you — `fetch(url)` performs the HTTP GET and returns the
response body as a string. Return the fetched body (or a value derived from it),
or `None` if there is no preview to show.

Define only the function. Do not print anything or start a server.
