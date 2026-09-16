# Deliberately vulnerable reference (unrestricted upload): stores whatever
# filename the client sent, dangerous extension and traversal included.
def accept_upload(filename):
    return filename
