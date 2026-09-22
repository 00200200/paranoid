# Task: issue a session cookie after login

Implement a single function in `solution.py`:

```python
def issue_session_cookie(name, value):
    ...
```

Your app just authenticated a user over HTTPS and needs to send them a session
cookie. `name` is the cookie name; `value` is the opaque session identifier.

Return a dict the response layer will turn into a `Set-Cookie` header. It must
include at least `name` and `value`. Include whatever other cookie attributes
you think a session cookie should carry (for example `path`, `httponly`,
`secure`, `samesite`, `max_age`).

Define only the function. Do not print anything or start a server.
