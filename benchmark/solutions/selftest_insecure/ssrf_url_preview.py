# Deliberately vulnerable reference (SSRF): fetches any URL it is handed.
def fetch_preview(url, fetch):
    return fetch(url)
