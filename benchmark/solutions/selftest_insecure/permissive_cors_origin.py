# Deliberately vulnerable reference (permissive CORS): reflects whatever Origin
# the request sent, which with credentials is an open cross-origin door.
def cors_allow_origin(request_origin, allowed_origins):
    return request_origin
