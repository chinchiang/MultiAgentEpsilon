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


CONTAINER = 'epsilon-isolated-' + 'a' * 16 + '-app'
ENVELOPE = json.dumps({'status': 200, 'headers': [], 'body': ''}).encode()


def test_bridge_timeout_is_a_distinct_deadline_error():
    # 呼叫端靠這個型別把橋接逾時與其他錯誤分開。 / Callers rely on this type to tell a bridge timeout from other errors.
    with pytest.raises(container_http.DeadlineExceeded, match='^container\\ HTTP\\ deadline\\ exceeded$'):
        container_http.bounded_output([sys.executable, '-c', 'import time; time.sleep(30)'], b'{}', timeout=0.2)
    assert issubclass(container_http.DeadlineExceeded, TimeoutError)


def test_child_that_closes_stdout_but_keeps_running_is_a_deadline_error():
    code = 'import os, time; os.close(1); time.sleep(30)'
    with pytest.raises(container_http.DeadlineExceeded):
        container_http.bounded_output([sys.executable, '-c', code], b'', timeout=0.5)


def test_request_timeout_is_capped_and_follows_the_evaluation_deadline(monkeypatch):
    seen = []
    monkeypatch.setattr(container_http, 'bounded_output', lambda *a, **kw: seen.append(kw['timeout']) or ENVELOPE)
    monkeypatch.setattr(container_http.time, 'monotonic', lambda: 100.0)
    container_http.BoundedClient(CONTAINER).get('/health')
    container_http.BoundedClient(CONTAINER, deadline=100.0 + container_http.REQUEST_SECONDS + 5).get('/health')
    container_http.BoundedClient(CONTAINER, deadline=101.5).get('/health')
    assert seen == [container_http.REQUEST_SECONDS, container_http.REQUEST_SECONDS, 1.5]


@pytest.mark.parametrize('deadline', [100.0, 99.0])
def test_request_after_the_evaluation_deadline_starts_no_child(monkeypatch, deadline):
    started = []
    monkeypatch.setattr(container_http, 'bounded_output', lambda *a, **kw: started.append(a) or ENVELOPE)
    monkeypatch.setattr(container_http.time, 'monotonic', lambda: 100.0)
    with pytest.raises(container_http.DeadlineExceeded):
        container_http.BoundedClient(CONTAINER, deadline=deadline).get('/health')
    assert started == []


def test_request_cap_leaves_room_above_the_in_container_socket_timeout():
    from pathlib import Path
    import re
    source = (Path(__file__).resolve().parents[1] / 'security/runtime/request.py').read_text()
    inner = max(int(value) for value in re.findall(r'timeout\((\d+)\)|timeout=(\d+)', source) for value in value if value)
    assert container_http.REQUEST_SECONDS >= inner + 5


def test_unreapable_child_does_not_replace_the_original_error(monkeypatch):
    import subprocess

    class Stuck(subprocess.Popen):
        def wait(self, timeout=None):
            if timeout == 5:
                raise subprocess.TimeoutExpired(self.args, timeout)
            return super().wait(timeout)

    monkeypatch.setattr(container_http.bounded_output.__globals__['subprocess'], 'Popen', Stuck)
    with pytest.raises(ValueError, match='envelope too large'):
        container_http.bounded_output([sys.executable, '-c', 'import os; os.write(1,b"x"*200000)'], b'{}', limit=1024)
