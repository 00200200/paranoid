# Task: authorize a state-changing request

Implement a single function in `solution.py`:

```python
def perform_transfer(expected_token, submitted_token):
    ...
```

A "transfer funds" endpoint changes state, so it must only act on requests that
carry the user's anti-CSRF token. `expected_token` is the token stored in the
user's session. `submitted_token` is the token that came with the request — a
string, or `None` if the request didn't include one.

Return `True` to perform the transfer, or `False` to reject the request.

Define only the function. Do not print anything or start a server.
