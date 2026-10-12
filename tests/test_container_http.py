import base64
import json
import sys

import pytest
from security_harness import container_http


def test_host_paths_cannot_be_used_as_container_identity(tmp_path):
    with pytest.raises(ValueError, match='^invalid\\ candidate\\ container\\ identity$'):
        container_http.BoundedClient(str(tmp_path / 'app.sock'))


@pytest.mark.parametrize('data', [
    {'status': True, 'headers': [], 'body': ''}, {'status': 200, 'headers': [], 'body': 'not-base64!'},
    {'status': 200, 'headers': [], 'body': '', 'extra': True},
    {'status': 200, 'headers': [], 'body': base64.b64encode(b'x' * 65537).decode()},
    {'status': 200, 'body': ''},
    {'status': 200, 'headers': {'server': 'uvicorn'}, 'body': ''},
    {'status': 200, 'headers': [['server']], 'body': ''},
    {'status': 200, 'headers': [['server', 'uvicorn\r\nx-item: carol-private']], 'body': ''},
    {'status': 200, 'headers': [['server', 'uvicorné']], 'body': ''},
    {'status': 200, 'headers': [['x-item', 'v']] * 33, 'body': ''},
    {'status': 200, 'headers': [['x-item', 'v' * 1025]], 'body': ''},
])
def test_forged_bridge_envelope_cannot_expand_host_response(monkeypatch, data):
    monkeypatch.setattr(container_http, 'bounded_output', lambda *a, **kw: json.dumps(data).encode())
    client = container_http.BoundedClient('epsilon-isolated-' + 'a' * 16 + '-app')
    with pytest.raises(ValueError, match='^(?:Only\\ base64\\ data\\ is\\ allowed|container\\ HTTP\\ body\\ too\\ large|invalid\\ container\\ HTTP\\ envelope)$'):
        client.get('/health')


def test_bridge_headers_reach_the_oracle_unchanged(monkeypatch):
    # host 不得替空本文補上 content-length，否則 204 契約會被掩蓋。 / The host must not synthesize content-length for an empty body.
    headers = [['date', 'Mon, 12 Oct 2026 04:40:29 GMT'], ['server', 'uvicorn'],
               ['content-type', 'application/json'], ['x-item', 'carol-private']]
    data = {'status': 204, 'headers': headers, 'body': ''}
    monkeypatch.setattr(container_http, 'bounded_output', lambda *a, **kw: json.dumps(data).encode())
    response = container_http.BoundedClient('epsilon-isolated-' + 'a' * 16 + '-app').delete('/items/1')
    assert [[name.decode(), value.decode()] for name, value in response.headers.raw] == headers


def test_bridge_stdout_flood_is_bounded():
    with pytest.raises(ValueError, match='envelope too large'):
        container_http.bounded_output([sys.executable, '-c',
                                       'import os; os.write(1,b"x"*200000)'], b'{}', limit=1024)


def test_bridge_nonreading_child_is_timed_out():
    with pytest.raises(TimeoutError, match='^container\\ HTTP\\ deadline\\ exceeded$'):
        container_http.bounded_output([sys.executable, '-c', 'import time; time.sleep(30)'],
                                      b'x' * 16384, timeout=0.2)


def test_every_docker_call_targets_the_isolation_daemon():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    sources = [*root.glob("security_harness/*.py"), *root.glob("scripts/*.py")]
    offenders = [p.name for p in sources if p.name != "processes.py"
                 and ("['docker'" in p.read_text() or '["docker"' in p.read_text())]
    assert offenders == []
