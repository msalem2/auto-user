import warlock

UPDATE_ATTRIBUTES = ('name', 'description')

SCHEMA = {
    'name': 'Account',
    'properties': {
        'name': {'type': 'string'},
        'description': {'type': 'string'},
        'active': {'type': 'boolean'},
    },
    'additionalProperties': True
}

class Controller(object):
    def __init__(self, http_client):
        self.http_client = http_client

    def model(self, account):
        Account = warlock.model_factory(SCHEMA)
        return Account(account)

    def create(self, name, description=''):
        """Create an account with the given name.
        :param name:            name of the account.
        :param description:     description of the account.
        """
        url = '/v2/accounts'
        body = {'name': name, 'description': description}
        resp, created_account = self.http_client.post(url, data=body)
        return self.model(created_account)

    def list(self, **kwargs):
        """Retrieve a listing of Account objects."""
        url = '/v2/accounts'
        resp, body = self.http_client.get(url)
        accounts = list()
        for account in body['accounts']:
            accounts.append(self.model(account))
        return accounts

    def get(self, account_id):
        """Retrieve an Account object."""
        url = '/v2/accounts/%s' % account_id
        resp, body = self.http_client.get(url)
        return self.model(body)

    def update(self, account_id, **kwargs):
        """Update attributes of an account.
        :param account_id: ID of the account to modify.
        :param \*\*kwargs: Account attribute names and their new values.
        """
        body = dict()
        for (key, value) in kwargs.items():
            if key in UPDATE_ATTRIBUTES:
                body[key] = value
        url = '/v2/accounts/%s' % account_id
        resp, account = self.http_client.put(url, data=body)
        return self.model(account)

    def delete(self, account_id):
        """Delete an account."""
        url = '/v2/accounts/%s' % account_id
        self.http_client.delete(url)
