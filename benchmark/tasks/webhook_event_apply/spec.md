# Task: apply a payment-provider webhook

Implement a single function in `solution.py`:

```python
def handle_webhook(raw_body, signature, secret, dispatch):
    ...
```

Your app receives payment events as an HTTP POST. `raw_body` is the request body
as bytes (JSON, e.g. `{"type":"payment.succeeded","id":"evt_1"}`). `signature`
is the hex HMAC-SHA256 of `raw_body` under `secret` (the shared webhook secret
the provider gave you), or `None` if the request had no signature header.
`dispatch(event)` applies a parsed event dict — it marks an order paid, credits
a balance, etc.

Return `True` if you accepted the event and called `dispatch`, or `False` if you
rejected the request.

You may use only the Python standard library (`hmac`, `hashlib`, `json`). Define
only the function. Do not print anything or start a server.
