import warlock

UPDATE_ATTRIBUTES = ('name', 'description')

SCHEMA = {
    'name': 'Domain',
    'properties': {
        'name': {'type': 'string'},
        'description': {'type': 'string'},
        'enabled': {'type': 'boolean'},
    },
    'additionalProperties': True
}


class Controller(object):
    def __init__(self, http_client):
        self.http_client = http_client

    def model(self, domain):
        Domain = warlock.model_factory(SCHEMA)
        return Domain(domain)

    def create(self, account_id, name, description=''):
        """Create a domain with the given name.
        :param account_id:      ID of the account.
        :param name:            name of the domain.
        :param description:     description of the domain.
        """
        url = '/v2/accounts/%s/domains' % account_id
        body = {'name': name, 'description': description}
        resp, created_domain = self.http_client.post(url, data=body)
        return self.model(created_domain)

    def list(self, account_id=None):
        """Retrieve a listing of Domain objects.
        :param account_id: ID of the account.
        """
        if account_id:
            url = '/v2/accounts/%s/domains' % account_id
        else:
            url = '/v2/accounts/domains'
        resp, body = self.http_client.get(url)
        domains = list()
        for domain in body['domains']:
            domains.append(self.model(domain))
        return domains

    def update(self, domain_id, account_id, **kwargs):
        """Update attributes of a Domain.
        :param domain_id:  ID of the domain to be updated.
        :param account_id: ID of the account.
        :param \*\*kwargs: Domain attribute names and their new values.
        """
        body = dict()
        for (key, value) in kwargs.items():
            if key in UPDATE_ATTRIBUTES:
                body[key] = value
        url = '/v2/accounts/%s/domains/%s' % (account_id, domain_id)
        resp, domain = self.http_client.put(url, data=body)
        return self.model(domain)

    def delete(self, domain_id, account_id):
        """Delete an domain."""
        url = '/v2/accounts/%s/domains/%s' % (account_id, domain_id)
        self.http_client.delete(url)
