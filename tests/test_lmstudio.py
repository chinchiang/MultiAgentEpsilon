"""地端協定與邊界回歸；Local protocol and boundary regressions (no real model)."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from security_harness.llm.gateway import Gateway, Request
from security_harness.llm.lmstudio import LMStudioAdapter, LMStudioHTTP, endpoint
from security_harness.llm.transport import validate_url
from security_harness.llm.benchmark import load_cases, review_request, make_plan

MODEL = 'nvidia/nemotron-3-nano-omni'
BASE = 'http://127.0.0.1:1234/v1'


def envelope():
    return {'model': MODEL, 'choices': [{'finish_reason': 'stop', 'message': {
        'role': 'assistant', 'content': 'EPSILON_SYNTHETIC_OK'}}],
        'usage': {'prompt_tokens': 12, 'completion_tokens': 8}}


def fixture(answer=None, models=None, status=200):
    wire = []
    class Stream(httpx.AsyncByteStream):
        def __init__(self, value): self.data = json.dumps(value).encode()
        async def __aiter__(self): yield self.data
    def response(status, value):
        return httpx.Response(status, headers={'Content-Type': 'application/json'}, stream=Stream(value))
    def handle(request):
        wire.append(request)
        value = ({'object': 'list', 'data': [{'id': MODEL}]} if models is None else models)
        if request.url.path.endswith('/models'):
            return response(200, value)
        return response(status, envelope() if answer is None else answer)
    http = LMStudioHTTP(BASE, transport=httpx.MockTransport(handle))
    return LMStudioAdapter(MODEL, BASE, 'synthetic-local-key', http), wire


@pytest.mark.parametrize('url', [
    'http://localhost:1234/v1', 'http://127.0.0.2:1234/v1', 'http://2130706433:1234/v1',
    'http://127.1:1234/v1', 'http://0.0.0.0:1234/v1', 'http://192.168.1.2:1234/v1',
    'http://169.254.169.254:1234/v1', 'http://[::ffff:127.0.0.1]:1234/v1',
    'http://127.0.0.1/v1', 'http://127.0.0.1:80/v1', 'http://127.0.0.1:65536/v1',
    'http://user@127.0.0.1:1234/v1', 'http://@127.0.0.1:1234/v1',
    'http://127.0.0.1:1234/v1?', 'http://127.0.0.1:1234/v1#',
    'http://127.0.0.1:1234/v1/../v1', 'http://127.0.0.1:1234/%76%31',
    'http://127.0.0.1:1234/v1/', ' http://127.0.0.1:1234/v1',
    'http://127.0.0.1:1234/\nv1', 'http://127.0.0.1:1234\\@evil.test/v1',
    'https://local.example.test:1234/v1', 'file:///v1',
])
def test_unapproved_destinations_are_configuration_errors(url):
    with pytest.raises(Exception, match='CONFIGURATION'):
        endpoint(url)


@pytest.mark.parametrize('url,local', [(BASE, True), ('http://[::1]:1234/v1', True),
                                    ('https://lm.example.test/v1', False)])
def test_only_literal_loopback_uses_direct_http(url, local):
    assert endpoint(url) is local
    assert LMStudioHTTP(url).trust_env is not local
    if local:
        with pytest.raises(Exception, match='CONFIGURATION'):
            validate_url(url)  # 雲端規則不放寬；Cloud policy remains HTTPS-only.


def test_discovery_precedes_inference_and_binds_model_and_schema():
    adapter, wire = fixture()
    request = review_request(load_cases()['B13'], 'opaque-synthetic-id', 1024)
    reply = asyncio.run(adapter.generate(request))
    assert reply.model_version == MODEL and adapter.family == 'nemotron'
    assert [r.method for r in wire] == ['GET', 'POST']
    assert [r.url.path for r in wire] == ['/v1/models', '/v1/chat/completions']
    payload = json.loads(wire[1].content)
    assert payload['response_format']['json_schema']['strict'] is True
    assert payload['response_format']['json_schema']['schema']['additionalProperties'] is False
    assert payload['model'] == MODEL and payload['max_tokens'] == 1024 and payload['stream'] is False
    assert 'Authorization' in wire[0].headers and 'x-goog-api-key' not in wire[1].headers
    assert 'tools' not in payload and payload['messages'][0]['role'] == 'system'


@pytest.mark.parametrize('models', [
    {}, {'object': 'list', 'data': []}, {'object': 'list', 'data': [None]},
    {'object': 'list', 'data': [{'id': 'wrong-model'}]},
    {'object': 'list', 'data': [{'id': MODEL}, {'id': MODEL}]},
])
def test_unavailable_or_ambiguous_model_never_receives_prompt(models):
    adapter, wire = fixture(models=models)
    gateway = Gateway()
    assert asyncio.run(gateway.generate(adapter, Request('synthetic', 'synthetic'))) is None
    assert len(wire) == 1 and wire[0].method == 'GET'
    assert gateway.evidence[0]['status'] == 'ERROR'


@pytest.mark.parametrize('attack,code', [
    ('model-switch', 'INVALID_RESPONSE'), ('model-missing', 'INVALID_RESPONSE'),
    ('choices-type', 'INVALID_RESPONSE'), ('choice-type', 'INVALID_RESPONSE'),
    ('multimodal', 'INVALID_RESPONSE'), ('tools', 'TOOL_REQUEST'),
    ('length', 'TRUNCATED'), ('refusal', 'REFUSED'), ('usage', 'INVALID_RESPONSE'),
])
def test_invalid_or_truncated_responses_never_succeed(attack, code):
    value = envelope()
    if attack == 'model-switch': value['model'] = 'another-model'
    elif attack == 'model-missing': value.pop('model')
    elif attack == 'choices-type': value['choices'] = {}
    elif attack == 'choice-type': value['choices'] = [None]
    elif attack == 'multimodal': value['choices'][0]['message']['content'] = [{'type': 'image'}]
    elif attack == 'tools': value['choices'][0]['message']['tool_calls'] = [{'name': 'shell'}]
    elif attack == 'length': value['choices'][0]['finish_reason'] = 'length'
    elif attack == 'refusal': value['choices'][0]['message']['refusal'] = 'synthetic'
    else: value['usage']['completion_tokens'] = True
    adapter, _ = fixture(answer=value); gateway = Gateway()
    assert asyncio.run(gateway.generate(adapter, Request('synthetic', 'synthetic'))) is None
    assert gateway.evidence[0]['code'] == code


@pytest.mark.parametrize('status,code', [(302, 'REDIRECT'), (401, 'AUTHENTICATION'),
                                      (403, 'AUTHENTICATION'), (429, 'RATE_LIMIT'), (500, 'HTTP_ERROR')])
def test_http_errors_are_bounded_and_redacted(status, code):
    adapter, wire = fixture(answer={'error': 'synthetic-secret-error'}, status=status)
    g = Gateway()
    assert asyncio.run(g.generate(adapter, Request('synthetic', 'synthetic'))) is None
    assert g.evidence[0]['code'] == code and len(wire) == 2
    assert 'synthetic-secret' not in json.dumps(g.evidence)


def test_http_client_cannot_change_destination():
    http = LMStudioHTTP(BASE)
    for url in ('http://127.0.0.1:4321/v1/models', BASE + '/models?next=1', BASE + '/admin'):
        with pytest.raises(Exception, match='CONFIGURATION'):
            asyncio.run(http.get(url, {}))


def test_cancellation_and_deadline_close_the_response_stream():
    class Delayed(httpx.AsyncByteStream):
        def __init__(self): self.closed = False
        async def __aiter__(self):
            await asyncio.sleep(60)
            yield b'{}'
        async def aclose(self): self.closed = True
    async def exercise(cancel):
        from security_harness.llm.gateway import Limits
        stream = Delayed()
        transport = httpx.MockTransport(lambda _: httpx.Response(200,
            headers={'Content-Type': 'application/json'}, stream=stream))
        adapter = LMStudioAdapter(MODEL, BASE, http=LMStudioHTTP(BASE, transport=transport))
        gateway = Gateway(Limits(timeout_seconds=0.02))
        task = asyncio.create_task(gateway.generate(adapter, Request('synthetic', 'synthetic')))
        if cancel:
            await asyncio.sleep(0.005); task.cancel()
            with pytest.raises(asyncio.CancelledError): await task
        else:
            assert await task is None
        assert stream.closed
        assert gateway.evidence[0]['status'] == ('CANCELLED' if cancel else 'TIMEOUT')
    asyncio.run(exercise(False)); asyncio.run(exercise(True))


def test_configured_lmstudio_keeps_glm_separate(monkeypatch):
    from scripts.model_smoke import configured_adapter
    monkeypatch.setenv('LMSTUDIO_MODEL_ID', MODEL); monkeypatch.setenv('LMSTUDIO_BASE_URL', BASE)
    monkeypatch.delenv('LMSTUDIO_API_KEY', raising=False)
    monkeypatch.setenv('GLM_CHAT_URL', 'invalid-unrelated-setting')
    adapter = configured_adapter('lmstudio')
    assert adapter.provider == 'lmstudio' and adapter._api_key is None


def test_live_lmstudio_cli_requires_explicit_opt_in(monkeypatch):
    import scripts.model_review as review
    monkeypatch.setattr('sys.argv', ['model_review', '--provider', 'lmstudio', '--case', 'B13'])
    with pytest.raises(SystemExit) as error: review.main()
    assert error.value.code == 2


def test_three_family_plan_fits_budget_only_when_batched():
    from security_harness.llm.benchmark_runner import initial_report
    providers = ['gemini', 'bedrock', 'lmstudio']
    r = initial_report(providers, ['B13', 'B14'], 'synthetic-run', 1024)
    assert len(r['plan']) == 6 and r['limits']['reserved_output_tokens'] == 6144
    with pytest.raises(ValueError):
        initial_report(providers, ['B13', 'B14'], 'synthetic-run', 1024, 2)


def test_real_loopback_protocol_fixture_stops_cleanly():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            self.send({'object': 'list', 'data': [{'id': MODEL}]})
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert payload['model'] == MODEL
            self.send(envelope())
        def send(self, value):
            data = json.dumps(value).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        adapter = LMStudioAdapter(MODEL, f'http://127.0.0.1:{server.server_port}/v1')
        g = Gateway(); reply = asyncio.run(g.generate(adapter, Request('synthetic', 'synthetic')))
        assert reply.text == 'EPSILON_SYNTHETIC_OK' and g.evidence[0]['status'] == 'SUCCESS'
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
    assert not thread.is_alive()


def test_five_provider_smoke_keeps_existing_deadline_cap():
    from scripts.model_smoke import initial_report
    import uuid
    report = initial_report(['mock', 'gemini', 'bedrock', 'glm', 'lmstudio'], str(uuid.uuid4()))
    assert report['total_timeout_seconds'] == 130
    assert report['limits']['max_calls'] == 5
    assert report['limits']['reserved_output_tokens'] == 1280


def test_local_adapter_full_review_scoring_and_cleanup(tmp_path, monkeypatch):
    from tests.test_model_benchmark import collected
    from scripts import model_smoke
    from security_harness.llm.benchmark_score import reference
    wire = []
    class Stream(httpx.AsyncByteStream):
        def __init__(self, value): self.data = json.dumps(value).encode()
        async def __aiter__(self): yield self.data
    def handle(request):
        wire.append(request)
        if request.method == 'GET':
            value = {'object': 'list', 'data': [{'id': MODEL}]}
        else:
            payload = json.loads(request.content)
            item = json.loads(payload['messages'][1]['content'])
            case_id = next(k for k, v in load_cases().items() if v['source'] == item['source'])
            truth = reference()[case_id]
            findings = [{**f, 'evidence': item['source'].splitlines()[f['line'] - 1].strip(),
                         'rationale': 'Synthetic reference fixture.'} for f in truth['findings']]
            review = {'review_id': item['review_id'], 'verdict': truth['verdict'],
                      'findings': findings, 'reason': 'Synthetic protocol fixture, not a model judgment.'}
            value = envelope()
            value['choices'][0]['message']['content'] = json.dumps(review)
        return httpx.Response(200, headers={'Content-Type': 'application/json'}, stream=Stream(value))
    def configured(provider, work, http):
        assert provider == 'lmstudio'
        return LMStudioAdapter(MODEL, BASE, http=LMStudioHTTP(BASE, transport=httpx.MockTransport(handle)))
    monkeypatch.setattr(model_smoke, 'configured_adapter', configured)
    report, path = collected(tmp_path, providers=['lmstudio'], case_ids=['B13', 'B14'])
    assert report['status'] == 'COMPLETE' and report['cleanup']['completed'] is True
    assert report['analysis']['provider_metrics']['lmstudio']['tp'] == 1
    assert report['analysis']['provider_metrics']['lmstudio']['tn'] == 1
    assert [r.method for r in wire] == ['GET', 'POST', 'GET', 'POST']
    assert not (tmp_path / '.state/runs' / report['run_id']).exists()
    assert MODEL in path.read_text() and BASE not in path.read_text()
