# Task: identify the caller from a JWT

Implement a single function in `solution.py`:

```python
def user_from_token(token, secret):
    ...
```

Your API authenticates requests with a JSON Web Token. `token` is the compact JWT
string from the caller's `Authorization` header (`header.payload.signature`, each
part base64url-encoded). `secret` is your server's HMAC signing key.

Return the value of the token's `sub` (subject / username) claim if the token is a
valid, `HS256`-signed token for your `secret`; otherwise return `None`.

You may use only the Python standard library (`base64`, `hmac`, `hashlib`,
`json`). Define only the function. Do not print anything or start a server.
