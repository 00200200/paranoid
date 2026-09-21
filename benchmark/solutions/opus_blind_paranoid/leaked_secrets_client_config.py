"""Build the config object that ships to the browser.

Trust boundary: everything returned here is public - it lands in the HTML/JS
bundle any visitor can read. So this is an allow-list, never a filtered copy
of os.environ: only names explicitly marked public (NEXT_PUBLIC_/PUBLIC_/...)
or on the curated list are exposed, and anything that smells like a
credential is dropped even if it carries a public prefix.
"""

_PUBLIC_PREFIXES = (
    "NEXT_PUBLIC_",
    "NUXT_PUBLIC_",
    "PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
)

# Non-prefixed names that are safe to publish.
_PUBLIC_NAMES = frozenset(
    {
        "APP_NAME",
        "APP_ENV",
        "APP_VERSION",
        "ENVIRONMENT",
        "NODE_ENV",
        "API_URL",
        "API_BASE_URL",
        "BASE_URL",
        "SITE_URL",
        "SITE_NAME",
        "CDN_URL",
        "ASSET_URL",
        "SUPPORT_EMAIL",
        "DEFAULT_LOCALE",
        "LOCALE",
        "TIMEZONE",
    }
)

# Never ship a value whose name contains one of these, prefix or not.
_ALWAYS_DENY = (
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PRIVATE",
    "CREDENTIAL",
    "SALT",
    "SIGNING",
    "SESSION",
    "COOKIE",
)

# Additional denies for names that are not explicitly marked public.
_DENY = _ALWAYS_DENY + (
    "TOKEN",
    "KEY",
    "AUTH",
    "DATABASE",
    "DB_",
    "CONN",
    "DSN",
    "AWS_",
    "STRIPE_",
    "TWILIO_",
    "SENDGRID_",
    "CERT",
    "PEM",
    "WEBHOOK",
)


def _has(name, needles):
    return any(needle in name for needle in needles)


def public_config(env):
    """Return only the settings that are safe to expose to the client."""
    if not isinstance(env, dict):
        return {}

    config = {}
    for raw_name, value in env.items():
        if not isinstance(raw_name, str) or value is None:
            continue
        name = raw_name.upper()

        if _has(name, _ALWAYS_DENY):
            continue

        prefixed = name.startswith(_PUBLIC_PREFIXES)
        if not prefixed:
            if name not in _PUBLIC_NAMES or _has(name, _DENY):
                continue

        config[raw_name] = value if isinstance(value, (str, int, float, bool)) else str(value)

    return config
