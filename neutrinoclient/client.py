import logging
import neutrinoclient.v1.client as v1_client
from neutrinoclient.common import utils

_logger = logging.getLogger(__name__)

_CLIENT_VERSIONS = {'1': v1_client.Client}

def Client(version=None, endpoint=None, session=None, *args, **kwargs):

    if not endpoint:
        msg = ('You must provide an endpoint')
        raise RuntimeError(msg)

    if not session:
        msg = ('You must provide a Keystone session')
        raise RuntimeError(msg)

    endpoint, url_version = utils.strip_version(endpoint)
    version = version or url_version

    if not version:
        msg = ("Please provide either the version or an url with the form "
               "http://$HOST:$PORT/v$VERSION_NUMBER")
        raise RuntimeError(msg)

    try:
        client_class = _CLIENT_VERSIONS[version]
    except KeyError:
        msg = ('No client available for version: %s') % version
        raise RuntimeError(msg)

    return client_class(endpoint, session, *args, **kwargs)
