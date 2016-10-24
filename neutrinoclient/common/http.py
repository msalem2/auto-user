import copy
import logging
import socket

from keystoneclient import adapter
from keystoneclient import exceptions as ksc_exc
from oslo_utils import importutils
from oslo_utils import netutils
import requests
import six
import warnings

try:
    import json
except ImportError:
    import simplejson as json

from oslo_utils import encodeutils

from neutrinoclient.common import utils
from neutrinoclient import exc

LOG = logging.getLogger(__name__)
USER_AGENT = 'python-neutrinoclient'


class HTTPClient(object):

    def __init__(self, endpoint, session, **kwargs):
        self.endpoint = endpoint
        self.auth_token = session.get_token()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT

        if self.auth_token:
            self.session.headers["X-Auth-Token"] = encodeutils.safe_encode(
                self.auth_token)

        self.timeout = float(kwargs.get('timeout', 600))

        if self.endpoint.startswith("https"):
            compression = True
            if kwargs.get('insecure', False) is True:
                self.session.verify = False
            else:
                if kwargs.get('cacert', None) is not '':
                    self.session.verify = kwargs.get('cacert', True)

            self.session.cert = (kwargs.get('cert_file'),
                                 kwargs.get('key_file'))


    @staticmethod
    def parse_endpoint(endpoint):
        return netutils.urlsplit(endpoint)

    def log_curl_request(self, method, url, headers, data, kwargs):
        curl = ['curl -g -i -X %s' % method]

        headers = copy.deepcopy(headers)
        headers.update(self.session.headers)

        for (key, value) in six.iteritems(headers):
            header = '-H \'%s: %s\'' % utils.safe_header(key, value)
            curl.append(header)

        if not self.session.verify:
            curl.append('-k')
        else:
            if isinstance(self.session.verify, six.string_types):
                curl.append(' --cacert %s' % self.session.verify)

        if self.session.cert:
            curl.append(' --cert %s --key %s' % self.session.cert)

        if data and isinstance(data, six.string_types):
            curl.append('-d \'%s\'' % data)

        curl.append(url)

        msg = ' '.join([encodeutils.safe_decode(item, errors='ignore')
                        for item in curl])
        LOG.debug(msg)

    @staticmethod
    def log_http_response(resp):
        status = (resp.raw.version / 10.0, resp.status_code, resp.reason)
        dump = ['\nHTTP/%.1f %s %s' % status]
        headers = resp.headers.items()
        dump.extend(['%s: %s' % utils.safe_header(k, v) for k, v in headers])
        dump.append('')
        content_type = resp.headers.get('Content-Type')

        if content_type != 'application/octet-stream':
            dump.extend([resp.text, ''])
        LOG.debug('\n'.join([encodeutils.safe_decode(x, errors='ignore')
                             for x in dump]))

    @staticmethod
    def encode_headers(headers):
        """Encodes headers.

        Note: This should be used right before
        sending anything out.

        :param headers: Headers to encode
        :returns: Dictionary with encoded headers'
                  names and values
        """
        return dict((encodeutils.safe_encode(h), encodeutils.safe_encode(v))
                    for h, v in six.iteritems(headers) if v is not None)

    def _handle_response(self, resp):
        if not resp.ok:
            LOG.debug("Request returned failure status %s." % resp.status_code)
            raise exc.from_response(resp, resp.content)

        content_type = resp.headers.get('Content-Type')

        content = resp.text
        if content_type and content_type.startswith('application/json'):
            # Let's use requests json method, it should take care of
            # response encoding
            body_iter = resp.json()
        else:
            body_iter = six.StringIO(content)
            try:
                body_iter = json.loads(''.join([c for c in body_iter]))
            except ValueError:
                body_iter = None

        return resp, body_iter

    def _request(self, method, url, **kwargs):
        """Send an http request with the specified characteristics.

        Wrapper around httplib.HTTP(S)Connection.request to handle tasks such
        as setting headers and error handling.
        """
        # Copy the kwargs so we can reuse the original in case of redirects
        headers = copy.deepcopy(kwargs.pop('headers', {}))

        # Note(flaper87): Before letting headers / url fly,
        # they should be encoded otherwise httplib will
        # complain.
        headers = self.encode_headers(headers)

        data = kwargs.pop("data", None)

        if data is not None and not isinstance(data, six.string_types):
            try:
                data = json.dumps(data)
                headers['Content-Type'] = 'application/json'
            except TypeError:
                pass

        if self.endpoint.endswith("/") or url.startswith("/"):
            conn_url = "%s%s" % (self.endpoint, url)
        else:
            conn_url = "%s/%s" % (self.endpoint, url)

        self.log_curl_request(method, conn_url, headers, data, kwargs)

        try:
            resp = self.session.request(method,
                                        conn_url,
                                        data=data,
                                        headers=headers,
                                        **kwargs)
        except requests.exceptions.Timeout as e:
            message = ("Error communicating with %(url)s: %(e)s" %
                       dict(url=conn_url, e=e))
            raise exc.InvalidEndpoint(message=message)
        except requests.exceptions.ConnectionError as e:
            message = ("Error finding address for %(url)s: %(e)s" %
                       dict(url=conn_url, e=e))
            raise exc.CommunicationError(message=message)
        except socket.gaierror as e:
            message = "Error finding address for %s: %s" % (
                self.endpoint_hostname, e)
            raise exc.InvalidEndpoint(message=message)
        except (socket.error, socket.timeout) as e:
            endpoint = self.endpoint
            message = ("Error communicating with %(endpoint)s %(e)s" %
                       {'endpoint': endpoint, 'e': e})
            raise exc.CommunicationError(message=message)

        resp, body_iter = self._handle_response(resp)
        self.log_http_response(resp)
        return resp, body_iter

    def head(self, url, **kwargs):
        return self._request('HEAD', url, **kwargs)

    def get(self, url, **kwargs):
        return self._request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self._request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        return self._request('PUT', url, **kwargs)

    def patch(self, url, **kwargs):
        return self._request('PATCH', url, **kwargs)

    def delete(self, url, **kwargs):
        return self._request('DELETE', url, **kwargs)


def get_http_client(endpoint, session, **kwargs):
    return HTTPClient(endpoint, session, **kwargs)
