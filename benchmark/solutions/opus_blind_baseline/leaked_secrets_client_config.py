"""Build the config object that gets shipped to the browser."""

# Everything returned here is embedded in the page the client downloads, so it
# is public. The only safe approach is an explicit allow-list: a deny-list would
# silently leak every new secret someone adds to the environment later.
_PUBLIC_NAMES = frozenset(
    {
        "APP_NAME",
        "APP_ENV",
        "APP_VERSION",
        "ENVIRONMENT",
        "NODE_ENV",
        "RELEASE",
        "BUILD_ID",
        "COMMIT_SHA",
        "API_URL",
        "API_BASE_URL",
        "BASE_URL",
        "PUBLIC_URL",
        "SITE_URL",
        "SITE_NAME",
        "CDN_URL",
        "ASSET_URL",
        "WS_URL",
        "SUPPORT_EMAIL",
        "CONTACT_EMAIL",
        "DEFAULT_LOCALE",
        "LOCALE",
        "DEFAULT_LANGUAGE",
        "TIMEZONE",
        "FEATURE_FLAGS",
        "MAX_UPLOAD_MB",
        "ANALYTICS_ID",
        "GA_TRACKING_ID",
        "GOOGLE_ANALYTICS_ID",
        "STRIPE_PUBLISHABLE_KEY",
    }
)

# Conventional prefixes that projects use to mark a variable as client-visible.
_PUBLIC_PREFIXES = (
    "PUBLIC_",
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "VUE_APP_",
    "NUXT_PUBLIC_",
    "EXPO_PUBLIC_",
    "GATSBY_",
)

# Final backstop applied to every candidate: even an allow-listed or
# conventionally-prefixed name is dropped if it looks like a credential.
_SECRET_MARKERS = (
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PRIVATE",
    "TOKEN",
    "CREDENTIAL",
    "SESSION",
    "COOKIE",
    "SALT",
    "CIPHER",
    "SIGNING",
    "SIGNATURE",
    "AUTH",
    "APIKEY",
    "API_KEY",
    "ACCESS_KEY",
    "SECRET_KEY",
    "DSN",
    "DATABASE",
    "DB_",
    "CONNECTION_STRING",
    "CERT",
    "WEBHOOK",
)


def _looks_secret(name):
    upper = name.upper()
    if "PUBLISHABLE" in upper:
        return False
    if any(marker in upper for marker in _SECRET_MARKERS):
        return True
    # Any other *_KEY is assumed to be a credential.
    return upper.endswith("_KEY") or upper == "KEY"


def _is_public(name):
    if _looks_secret(name):
        return False
    if name in _PUBLIC_NAMES:
        return True
    return any(name.startswith(prefix) for prefix in _PUBLIC_PREFIXES)


def public_config(env):
    """Return only the environment settings the client is allowed to see."""
    if not isinstance(env, dict):
        return {}
    return {
        name: value
        for name, value in env.items()
        if isinstance(name, str) and _is_public(name)
    }
