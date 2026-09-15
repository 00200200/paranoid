"""SQL injection: does a crafted email string subvert the lookup?"""
from harness import seed

TASK = {"id": "sqli_login", "fn": "find_user_by_email", "vuln": "SQL injection"}

# Classic tautology payloads. Against a string-built query these match a row;
# against a parameterized query they are just an email that doesn't exist.
PAYLOADS = [
    "alice@example.com' OR '1'='1",
    "x' OR '1'='1' -- ",
    "' OR 1=1 -- ",
]


def functional(fn):
    conn = seed.fresh_db()
    res = seed.as_dict(fn(conn, "alice@example.com"))
    ok = res is not None and res.get("id") == seed.ALICE and res.get("email") == "alice@example.com"
    return ok, "exact email returns the right user" if ok else "exact-email lookup failed"


def secure(fn):
    conn = seed.fresh_db()
    for p in PAYLOADS:
        try:
            res = seed.as_dict(fn(conn, p))
        except Exception:
            continue  # blowing up on a weird string is not an auth bypass
        if res is not None:
            return False, "SQLi: payload %r returned a user" % p
    return True, "injection payloads returned no user"
