"""Trust boundary: everything returned here is shipped into the browser bundle,
so it is public forever. The server environment is treated as secret by default:
values are published only if the key is explicitly public (allow-list), and a
second pass drops anything whose name or value looks like a credential.
"""

_PUBLIC_PREFIXES = (
    "PUBLIC_",
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "VUE_APP_",
    "EXPO_PUBLIC_",
)

_PUBLIC_EXACT = frozenset(
    {
        "APP_NAME",
        "APP_ENV",
        "APP_URL",
        "APP_VERSION",
        "SITE_NAME",
        "SITE_URL",
        "ENVIRONMENT",
        "NODE_ENV",
        "DEFAULT_LOCALE",
        "DEFAULT_THEME",
        "LOCALE",
        "TIMEZONE",
        "SUPPORT_EMAIL",
        "API_BASE_URL",
        "CDN_URL",
    }
)

# Defence in depth: even an allow-listed / PUBLIC_-prefixed key is dropped if it
# smells like a credential (e.g. NEXT_PUBLIC_STRIPE_SECRET_KEY).
_SECRET_MARKERS = (
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "TOKEN",
    "PRIVATE",
    "CREDENTIAL",
    "CREDS",
    "API_KEY",
    "APIKEY",
    "_KEY",
    "KEY_",
    "SALT",
    "SIGNING",
    "SIGNATURE",
    "CERT",
    "SESSION",
    "COOKIE",
    "AUTH",
    "JWT",
    "OAUTH",
    "DSN",
    "DATABASE",
    "DB_",
    "CONNECTION_STRING",
    "CONN_STR",
    "WEBHOOK",
    "SMTP",
    "REDIS",
    "MONGO",
    "POSTGRES",
    "MYSQL",
    "AWS_",
    "AZURE_",
    "GCP_",
    "ADMIN",
    "MASTER",
    "SSN",
    "OTP",
)

_VALUE_SUBSTRINGS = ("-----BEGIN", "PRIVATE KEY")
_VALUE_PREFIXES = (
    "sk_",
    "sk-",
    "rk_",
    "shpat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "AKIA",
    "ASIA",
    "AIza",
    "eyJ",  # a JWT in client config is almost always a leaked credential
)
_MAX_VALUE_LEN = 2048


def _key_is_public(key):
    upper = key.upper()
    if upper in _PUBLIC_EXACT:
        allowed = True
    else:
        allowed = any(upper.startswith(prefix) for prefix in _PUBLIC_PREFIXES)
    if not allowed:
        return False
    if "PUBLISHABLE" in upper:  # e.g. NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY
        return True
    return not any(marker in upper for marker in _SECRET_MARKERS)


def _value_is_publishable(value):
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return True
    if not isinstance(value, str):
        return False  # never serialise arbitrary objects into the bundle
    if len(value) > _MAX_VALUE_LEN:
        return False
    if any(marker in value for marker in _VALUE_SUBSTRINGS):
        return False
    if any(value.startswith(prefix) for prefix in _VALUE_PREFIXES):
        return False
    # A URL carrying userinfo (postgres://user:pass@host) is a credential.
    scheme_split = value.split("://", 1)
    if len(scheme_split) == 2:
        authority = scheme_split[1].split("/", 1)[0]
        if "@" in authority and ":" in authority.split("@", 1)[0]:
            return False
    return True


def public_config(env):
    if not isinstance(env, dict):
        return {}
    config = {}
    for key, value in env.items():
        if not isinstance(key, str) or not key:
            continue
        if not _key_is_public(key):
            continue
        if not _value_is_publishable(value):
            continue
        config[key] = value
    return config
