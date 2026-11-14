"""host 不連接候選控制的檔案路徑；使用有限額的 exec 傳輸。

No host connection to candidate-owned filesystem paths; bounded exec transport."""
import base64
import json as json_codec
import re
import time

import httpx


from .processes import DeadlineExceeded, bounded_output, docker_command, docker_environment

# 每個請求的上限：容器內 request.py 自己有 3 秒 socket 逾時，其餘留給 docker exec 與直譯器啟動。 / Per-request cap:
# request.py inside the container has its own 3-second socket timeout; the rest covers docker exec and interpreter start.
REQUEST_SECONDS = 8
HEADER_TEXT = re.compile(r'[\x20-\x7e]{1,1024}')


class BoundedClient:
    def __init__(self, container, deadline=None):
        if not re.fullmatch(r'epsilon-isolated-[a-f0-9]{16}-app', container):
            raise ValueError('invalid candidate container identity')
        self.container = container
        # 整輪評估的 monotonic 期限；None 表示只受每請求上限約束。 / Monotonic deadline of the whole evaluation; None
        # leaves only the per-request cap.
        self.deadline = deadline

    def timeout(self):
        if self.deadline is None:
            return REQUEST_SECONDS
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExceeded('container HTTP deadline exceeded')
        return min(REQUEST_SECONDS, remaining)

    def request(self, method, path, *, headers=None, json=None):
        payload = json_codec.dumps({'method': method, 'path': path, 'headers': headers or {}, 'json': json}).encode()
        command = docker_command('exec', '-i', self.container, 'python', '-I', '/opt/epsilon/request.py')
        data = json_codec.loads(bounded_output(command, payload, timeout=self.timeout(), env=docker_environment()))
        if (not isinstance(data, dict) or set(data) != {'status', 'headers', 'body'} or
                type(data['status']) is not int or not 100 <= data['status'] <= 599 or
                not isinstance(data['headers'], list) or len(data['headers']) > 32 or
                not all(isinstance(pair, list) and len(pair) == 2 and
                        all(isinstance(part, str) and HEADER_TEXT.fullmatch(part) for part in pair)
                        for pair in data['headers']) or
                not isinstance(data['body'], str)):
            raise ValueError('invalid container HTTP envelope')
        body = base64.b64decode(data['body'], validate=True)
        if len(body) > 65536:
            raise ValueError('container HTTP body too large')
        return httpx.Response(data['status'], headers=[tuple(pair) for pair in data['headers']], content=body,
                              request=httpx.Request(method, 'http://localhost' + path))

    def get(self, path, **kwargs):
        return self.request('GET', path, **kwargs)

    def post(self, path, **kwargs):
        return self.request('POST', path, **kwargs)

    def patch(self, path, **kwargs):
        return self.request('PATCH', path, **kwargs)

    def delete(self, path, **kwargs):
        return self.request('DELETE', path, **kwargs)
