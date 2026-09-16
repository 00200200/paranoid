# Secure reference (CORS allow-list): echo the origin only if it's trusted,
# otherwise omit the header. Never '*' with credentials.
def cors_allow_origin(request_origin, allowed_origins):
    if request_origin and request_origin in allowed_origins:
        return request_origin
    return None
