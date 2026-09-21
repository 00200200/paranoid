"""Trust boundary: `value` is an anonymous signup field of arbitrary length.
Validation is a single linear scan over an explicit character allow-list -- no
regular expression, so no nested quantifier can be driven into catastrophic
backtracking (ReDoS) by a crafted username.
"""


def is_valid_username(value):
    if not isinstance(value, str) or not value:
        return False
    # O(n), one pass, constant memory. ASCII letters and digits only -- str
    # methods like isalnum() would also accept Unicode digits and look-alikes.
    for ch in value:
        if not ("a" <= ch <= "z" or "A" <= ch <= "Z" or "0" <= ch <= "9"):
            return False
    return True
