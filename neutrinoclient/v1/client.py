from neutrinoclient.common import utils, http
from neutrinoclient.v1 import accounts
from neutrinoclient.v1 import domains

class Client(object):
    """Client for the Neutrino v1 API.
    :param string endpoint: A user-supplied endpoint URL for the Neutrino
                            service.
    :param Session session: Keystone session.
    """
    def __init__(self, endpoint, session, **kwargs):
        endpoint, self.version = utils.endpoint_version_from_url(endpoint, 1)
        self.http_client = http.get_http_client(endpoint=endpoint, session=session, **kwargs)

        self.accounts = accounts.Controller(self.http_client)

        self.domains = domains.Controller(self.http_client)
