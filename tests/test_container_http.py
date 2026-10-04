import base64
import json
import sys

import pytest
from security_harness import container_http


def test_host_paths_cannot_be_used_as_container_identity(tmp_path):
    with pytest.raises(ValueError):
        container_http.BoundedClient(str(tmp_path / 'app.sock'))


@pytest.mark.parametrize('data', [
    {'status': True, 'body': ''}, {'status': 200, 'body': 'not-base64!'},
    {'status': 200, 'body': '', 'extra': True},
    {'status': 200, 'body': base64.b64encode(b'x' * 65537).decode()},
])
def test_forged_bridge_envelope_cannot_expand_host_response(monkeypatch, data):
    monkeypatch.setattr(container_http, 'bounded_output', lambda *a, **kw: json.dumps(data).encode())
    client = container_http.BoundedClient('epsilon-isolated-' + 'a' * 16 + '-app')
    with pytest.raises(ValueError):
        client.get('/health')


def test_bridge_stdout_flood_is_bounded():
    with pytest.raises(ValueError, match='envelope too large'):
        container_http.bounded_output([sys.executable, '-c',
                                       'import os; os.write(1,b"x"*200000)'], b'{}', limit=1024)


def test_bridge_nonreading_child_is_timed_out():
    with pytest.raises(TimeoutError):
        container_http.bounded_output([sys.executable, '-c', 'import time; time.sleep(30)'],
                                      b'x' * 16384, timeout=0.2)
