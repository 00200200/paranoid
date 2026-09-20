# Deliberately vulnerable reference (ReDoS): nested quantifiers. The accepted
# language is "one or more alphanumerics", but the extra + around the group is
# exponential when the match fails (a trailing '!').
import re


def is_valid_username(value):
    return bool(re.match(r"^([A-Za-z0-9]+)+$", value or ""))
