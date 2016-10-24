import six.moves.urllib.parse as urlparse
import re
import hashlib

SENSITIVE_HEADERS = ('X-Auth-Token', )

def strip_version(endpoint):
    """Strip version from the last component of endpoint if present."""
    version = None
    # Get rid of trailing '/' if present
    endpoint = endpoint.rstrip('/')
    url_parts = urlparse.urlparse(endpoint)
    (scheme, netloc, path, __, __, __) = url_parts
    path = path.lstrip('/')
    # regex to match 'v1' or 'v2.0' etc
    if re.match('v\d+\.?\d*', path):
        version = float(path.lstrip('v'))
        endpoint = scheme + '://' + netloc
    return endpoint, version

def endpoint_version_from_url(endpoint, default_version=None):
    if endpoint:
        endpoint, version = strip_version(endpoint)
        return endpoint, version or default_version
    else:
        return None, default_version

def safe_header(name, value):
    if value is not None and name in SENSITIVE_HEADERS:
        h = hashlib.sha1(value)
        d = h.hexdigest()
        return name, "{SHA1}%s" % d
    else:
        return name, value
