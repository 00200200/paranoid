"""Build the config object that is shipped to the browser.

Everything this returns is public: it is serialized into the bundle any
visitor can read.  So it is built from an allow-list of settings that are
safe to publish, rather than by removing the secrets we happen to think of.
"""

# Build-tool conventions for "this value is meant for the client".
_PUBLIC_PREFIXES = (
    "PUBLIC_",
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "VUE_APP_",
    "EXPO_PUBLIC_",
    "GATSBY_",
)

_PUBLIC_KEYS = frozenset(
    {
        "APP_NAME",
        "APP_ENV",
        "APP_URL",
        "APP_VERSION",
        "SITE_NAME",
        "SITE_URL",
        "BASE_URL",
        "API_URL",
        "API_BASE_URL",
        "API_ORIGIN",
        "CDN_URL",
        "ASSET_URL",
        "STATIC_URL",
        "MEDIA_URL",
        "ENV",
        "ENVIRONMENT",
        "BUILD_ID",
        "COMMIT_SHA",
        "RELEASE",
        "VERSION",
        "LOCALE",
        "DEFAULT_LOCALE",
        "THEME",
        "DEFAULT_THEME",
        "SUPPORT_EMAIL",
        "CONTACT_EMAIL",
        "DOCS_URL",
        "FEATURE_FLAGS",
        "STRIPE_PUBLISHABLE_KEY",
        "STRIPE_PUBLIC_KEY",
        "GA_TRACKING_ID",
        "ANALYTICS_ID",
    }
)

# Belt and braces: never emit a name that looks like a credential, even if it
# carries a "public" prefix.
_SECRET_MARKERS = (
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PRIVATE",
    "CREDENTIAL",
    "TOKEN",
    "SALT",
    "SIGNING",
    "SESSION",
    "COOKIE",
    "DATABASE",
    "CONNECTION",
    "CONN_STR",
    "ACCESS_KEY",
    "API_KEY",
    "APIKEY",
    "AUTH",
    "DSN",
    "CERT",
    "PASSPHRASE",
)


def public_config(env):
    if not isinstance(env, dict):
        return {}

    config = {}
    for key, value in env.items():
        if not isinstance(key, str):
            continue
        upper = key.upper()
        if any(marker in upper for marker in _SECRET_MARKERS):
            continue
        if upper in _PUBLIC_KEYS or upper.startswith(_PUBLIC_PREFIXES):
            if value is None or isinstance(value, (str, int, float, bool)):
                config[key] = value
    return config
