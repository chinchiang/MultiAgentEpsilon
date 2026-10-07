"""No host connection to candidate-owned filesystem paths; bounded exec transport."""
import base64
import json as json_codec
import re

import httpx


from .processes import bounded_output, docker_command, docker_environment


class BoundedClient:
    def __init__(self, container):
        if not re.fullmatch(r'epsilon-isolated-[a-f0-9]{16}-app', container):
            raise ValueError('invalid candidate container identity')
        self.container = container

    def request(self, method, path, *, headers=None, json=None):
        payload = json_codec.dumps({'method': method, 'path': path, 'headers': headers or {}, 'json': json}).encode()
        command = docker_command('exec', '-i', self.container, 'python', '-I', '/opt/epsilon/request.py')
        data = json_codec.loads(bounded_output(command, payload, env=docker_environment()))
        if (not isinstance(data, dict) or set(data) != {'status', 'body'} or
                type(data['status']) is not int or not 100 <= data['status'] <= 599 or
                not isinstance(data['body'], str)):
            raise ValueError('invalid container HTTP envelope')
        body = base64.b64decode(data['body'], validate=True)
        if len(body) > 65536:
            raise ValueError('container HTTP body too large')
        return httpx.Response(data['status'], content=body,
                              request=httpx.Request(method, 'http://localhost' + path))

    def get(self, path, **kwargs):
        return self.request('GET', path, **kwargs)

    def post(self, path, **kwargs):
        return self.request('POST', path, **kwargs)

    def patch(self, path, **kwargs):
        return self.request('PATCH', path, **kwargs)
