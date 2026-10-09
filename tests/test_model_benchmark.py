"""有標準答案的合成資料與對抗性盲審帳目驗證。

Truth-backed synthetic fixtures and adversarial blind-review accounting."""
import asyncio
import copy
import json
import os
import signal
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from security_harness.llm import benchmark as bench
from security_harness.llm import benchmark_score as score
from security_harness.llm import benchmark_runner as runner
from security_harness.llm import lifecycle as life
from security_harness.llm.gateway import ModelError, Reply, digest
from security_harness.lifecycle import prepare_run


from tests.model_evidence import provider_answer


@pytest.fixture(autouse=True)
def _no_model_evidence_left_in_artifacts():
    from tests.model_evidence import remove_new_model_evidence
    with remove_new_model_evidence(Path(__file__).resolve().parents[1]):
        yield

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('case_id', ['B01', 'B02', 'B05', 'B06'])
def test_sql_reference_has_executable_counterexample(case_id):
    case = bench.load_cases()[case_id]
    namespace = {}
    exec(case['source'], namespace)  # 只使用已納入版本管理的可信合成原碼。 / Only checked-in trusted synthetic fixture source.
    with sqlite3.connect(':memory:') as conn:
        conn.execute('CREATE TABLE items(id INTEGER, name TEXT)')
        conn.executemany('INSERT INTO items VALUES (?,?)', [(1, 'one'), (2, 'two')])
        assert namespace['lookup'](conn, 'one') == [(1,)]
        rows = namespace['lookup'](conn, "x' OR 1=1 --")
        assert rows == ([(1,), (2,)] if score.reference()[case_id]['verdict'] == 'VULNERABLE' else [])


@pytest.mark.parametrize('case_id', ['B03', 'B04'])
def test_command_reference_tracks_shell_boundary_without_executing_payload(case_id):
    namespace, calls = {}, []
    exec(bench.load_cases()[case_id]['source'], namespace)
    class Spy:
        def run(self, *args, **kwargs):
            calls.append((args, kwargs))
    namespace['subprocess'] = Spy()
    namespace['render']('synthetic; echo marker')
    args, options = calls[0]
    vulnerable = score.reference()[case_id]['verdict'] == 'VULNERABLE'
    assert options.get('shell', False) is vulnerable
    assert args[0] == ('printf synthetic; echo marker' if vulnerable else ['printf', '%s', 'synthetic; echo marker'])


def collected(tmp_path, providers=None, case_ids=None):
    report = runner.initial_report(providers or ['mock-review-a', 'mock-review-b'],
                                   case_ids or list(bench.SUITES['injection']), str(uuid.uuid4()))
    path = tmp_path / 'artifacts' / report['run_id'] / 'report.json'
    life.persist(path, report)
    prepare_run(tmp_path, report['run_id'], operation='model-smoke')
    code = asyncio.run(runner.run_worker(tmp_path, report['run_id']))
    data = life.finish(tmp_path, report['run_id'], providers=report['providers'], returncode=code, expected_report=report)
    return data, path


def test_blinding_projection_and_identical_requests_for_each_provider():
    plan = bench.make_plan(['mock-review-a', 'mock-review-b'], list(bench.SUITES['injection']))
    grouped = {}
    for item in plan:
        case = bench.load_cases()[item['case_id']]
        request = bench.review_request({**case, 'answer': 'must-not-leak', 'peer_reviews': 'hidden'}, item['review_id'])
        payload = json.loads(request.user)
        assert set(payload) == {'review_id', 'language', 'context', 'source'}
        assert 'must-not-leak' not in request.user and 'hidden' not in request.user
        assert item['case_id'] not in request.user
        grouped.setdefault(item['case_id'], []).append(request)
    assert all(requests[0] == requests[1] and requests[0] is not requests[1] for requests in grouped.values())
    assert len({p['review_id'] for p in plan}) == 6


def test_mock_disagreement_has_correct_denominators_and_never_claims_bias_reduction(tmp_path):
    report, _ = collected(tmp_path)
    assert report['status'] == 'COMPLETE' and report['cleanup']['completed']
    metrics = report['analysis']['provider_metrics']
    assert {k: metrics['mock-review-a'][k] for k in ('tp', 'tn', 'fp', 'fn')} == dict(tp=3, tn=3, fp=0, fn=0)
    assert {k: metrics['mock-review-b'][k] for k in ('tp', 'tn', 'fp', 'fn')} == dict(tp=3, tn=2, fp=1, fn=0)
    assert metrics['mock-review-b']['false_positive_rate_valid'] == 1 / 3
    assert metrics['mock-review-a']['input_tokens_reported'] is None
    assert metrics['mock-review-a']['usage_complete'] is False
    pair = report['analysis']['pairwise'][0]
    assert pair['comparable'] == 6 and pair['disagreements'] == 1 and pair['rate_comparable'] == 1 / 6
    pending = [c for c in report['analysis']['adjudication'] if c['status'] == 'PENDING_HUMAN_REVIEW']
    assert [c['case_id'] for c in pending] == ['B06']
    assert report['analysis']['live_family_labels_observed'] == []
    assert report['analysis']['bias_reduction'] == 'NOT_ESTABLISHED'
    assert report['analysis']['security_gate_effect'] == 'NONE'


def review_value(case_id='B01'):
    case = bench.load_cases()[case_id]
    token = str(uuid.uuid4())
    value = json.loads(asyncio.run(bench.MockReviewer('mock-review-a').generate(bench.review_request(case, token))).text)
    return case, token, value


@pytest.mark.parametrize('mutation', ['wrong-id', 'extra-field', 'bool-line', 'wrong-line', 'wrong-quote',
                                    'unknown-cwe', 'duplicate-finding', 'clean-with-finding', 'empty-positive',
                                    'oversize-reason', 'control-character', 'tool-request'])
def test_review_schema_rejects_untrusted_variants(mutation):
    case, token, value = review_value()
    finding = value['findings'][0]
    if mutation == 'wrong-id': value['review_id'] = str(uuid.uuid4())
    elif mutation == 'extra-field': value['approved'] = True
    elif mutation == 'bool-line': finding['line'] = True
    elif mutation == 'wrong-line': finding['line'] = 99
    elif mutation == 'wrong-quote': finding['evidence'] = 'fabricated evidence'
    elif mutation == 'unknown-cwe': finding['cwe'] = 'CWE-9999'
    elif mutation == 'duplicate-finding': value['findings'] *= 2
    elif mutation == 'clean-with-finding': value['verdict'] = 'CLEAN'
    elif mutation == 'empty-positive': value['findings'] = []
    elif mutation == 'oversize-reason': value['reason'] = 'x' * 401
    elif mutation == 'control-character': value['reason'] = 'run\ncommand'
    else: value['tool_calls'] = [{'name': 'shell'}]
    with pytest.raises(ModelError):
        bench.parse_review(json.dumps(value), case, token)


@pytest.mark.parametrize('raw', ['{"verdict":"CLEAN","verdict":"VULNERABLE"}', '```json\n{}\n```', '{"x":NaN}', '[]'])
def test_noncanonical_model_envelopes_rejected(raw):
    with pytest.raises(ModelError):
        bench.parse_review(raw, bench.load_cases()['B01'], str(uuid.uuid4()))


@pytest.mark.parametrize('failure', ['abstain', 'schema', 'timeout', 'refusal', 'configuration'])
def test_unassessed_cases_do_not_disappear_from_miss_rate(tmp_path, monkeypatch, failure):
    import scripts.model_smoke as smoke
    class Adapter(bench.MockReviewer):
        provider = 'gemini'
        family = 'gemini'
        def __init__(self): pass
        async def generate(self, request):
            if failure == 'timeout': raise TimeoutError()
            if failure == 'refusal': raise ModelError('REFUSED')
            if failure == 'schema': return Reply('private raw invalid response')
            value = {'review_id': json.loads(request.user)['review_id'], 'verdict': 'ABSTAIN',
                     'findings': [], 'reason': 'Insufficient evidence.'}
            return Reply(json.dumps(value))
    def factory(*args):
        if failure == 'configuration': raise ModelError('CONFIGURATION')
        return Adapter()
    monkeypatch.setattr(smoke, 'configured_adapter', factory)
    report, path = collected(tmp_path, ['gemini'], ['B01', 'B02'])
    metrics = report['analysis']['provider_metrics']['gemini']
    assert metrics['coverage'] == 0 and metrics['positive_miss_rate_all'] == 1
    assert metrics['false_negative_rate_valid'] is None and metrics['false_positive_rate_valid'] is None
    assert metrics['tn'] == 0 and metrics['tp'] == 0
    assert report['status'] == ('COMPLETE' if failure == 'abstain' else 'INCOMPLETE')
    # SINGLE_REVIEWER 本身就會待審；須驗證特定失敗原因。 / SINGLE_REVIEWER alone would make PENDING_HUMAN_REVIEW unconditional; require the specific cause.
    cause = 'ABSTAIN' if failure == 'abstain' else 'INCOMPLETE_REVIEW'
    assert all(c['status'] == 'PENDING_HUMAN_REVIEW' and cause in c['reasons'] for c in report['analysis']['adjudication'])
    assert 'private raw invalid response' not in path.read_text()


@pytest.mark.parametrize('mutation', ['missing-check', 'duplicate-call', 'wrong-case', 'stale-request',
                                    'stale-catalog', 'stale-oracle', 'changed-plan', 'swapped-review'])
def test_evidence_variants_cannot_fake_a_complete_benchmark(tmp_path, mutation):
    data, _ = collected(tmp_path, ['mock-review-a'], ['B01', 'B02'])
    original = copy.deepcopy(data['plan'])
    if mutation == 'missing-check': data['checks'].pop()
    elif mutation == 'duplicate-call': data['calls'][1] = data['calls'][0]
    elif mutation == 'wrong-case': data['checks'][0]['case_id'] = 'B06'
    elif mutation == 'stale-request': data['calls'][0]['request_sha256'] = '0' * 64
    elif mutation == 'stale-catalog': data['case_catalog_sha256'] = '0' * 64
    elif mutation == 'stale-oracle': data['oracle_sha256'] = '0' * 64
    elif mutation == 'changed-plan': data['plan'].reverse()
    else: data['checks'][0]['review'] = data['checks'][1]['review']
    with pytest.raises((ValueError, ModelError)):
        score.summarize(data, original)


def test_agreeing_wrong_models_still_require_human_review_and_localization_is_scored(tmp_path):
    data, _ = collected(tmp_path, case_ids=['B01'])
    for check in data['checks']:
        value = check['review']
        value.update(verdict='CLEAN', findings=[], reason='Incorrect synthetic conclusion.')
        provider_answer(data, check)
    analysis = score.summarize(data)
    assert analysis['pairwise'][0]['disagreements'] == 0
    assert analysis['adjudication'][0]['reasons'] == ['REFERENCE_MISMATCH']
    assert all(m['positive_miss_rate_all'] == 1 for m in analysis['provider_metrics'].values())
    check = data['checks'][0]
    check['review'].update(verdict='VULNERABLE', findings=[{'cwe': 'CWE-89', 'line': 1,
        'evidence': bench.load_cases()['B01']['source'].splitlines()[0], 'rationale': 'Wrong root-cause line.'}])
    provider_answer(data, check)
    metrics = score.summarize(data)['provider_metrics'][check['provider']]
    assert metrics['tp'] == 1 and metrics['finding_recall_all'] == 0


def test_cancelled_collection_keeps_all_planned_cases_in_analysis(tmp_path, monkeypatch):
    import scripts.model_smoke as smoke
    class Hang(bench.MockReviewer):
        provider, family = 'gemini', 'gemini'
        def __init__(self): pass
        async def generate(self, _):
            await asyncio.Event().wait()
    monkeypatch.setattr(smoke, 'configured_adapter', lambda *args: Hang())
    report = runner.initial_report(['gemini'], ['B01', 'B02'], str(uuid.uuid4()))
    life.persist(tmp_path / 'artifacts' / report['run_id'] / 'report.json', report)
    prepare_run(tmp_path, report['run_id'], operation='model-smoke')
    async def cancel():
        task = asyncio.create_task(runner.run_worker(tmp_path, report['run_id']))
        await asyncio.sleep(0.02)
        task.cancel()
        assert await task == 1
    asyncio.run(cancel())
    data = life.finish(tmp_path, report['run_id'], reason='CANCELLED', expected_report=report)
    assert data['status'] == 'CANCELLED' and data['cleanup']['completed']
    assert data['analysis']['provider_metrics']['gemini']['unavailable'] == 2


def test_adjudication_is_append_only_unsigned_and_bound_to_exact_report(tmp_path):
    report, path = collected(tmp_path, case_ids=['B06'])
    original = path.read_bytes()
    note_path = score.add_adjudication(path, 'B06', 'REFERENCE_CONFIRMED', 'synthetic-reviewer', 'Bound parameters preserve literal data.')
    note = json.loads(note_path.read_text())
    assert note['identity_verified'] is False and note['security_gate_effect'] == 'NONE'
    assert score.note_matches_report(note, path) and path.read_bytes() == original
    second = score.add_adjudication(path, 'B06', 'NEEDS_MORE_EVIDENCE', 'synthetic-reviewer', 'A separate test note.')
    assert second != note_path and note_path.exists()
    with pytest.raises(ValueError):
        score.add_adjudication(path, 'B06', 'ALLOW', 'synthetic-reviewer', 'Must never become a gate approval.')
    path.write_bytes(original + b' ')
    assert not score.note_matches_report(note, path)


def test_review_cli_supervision_and_explicit_live_opt_in():
    script = ROOT / 'scripts/model_review.py'
    done = subprocess.run([sys.executable, '-I', str(script)], capture_output=True, timeout=10)
    assert done.returncode == 0
    data = json.loads(Path(json.loads(done.stdout)['evidence']).read_text())
    assert data['status'] == 'COMPLETE' and data['cleanup']['completed'] and data['analysis']
    denied = subprocess.run([sys.executable, '-I', str(script), '--provider', 'gemini'], capture_output=True, timeout=10)
    assert denied.returncode == 2
    # 此程序不取得憑證或供應商設定，回歸也不能花費真實呼叫。 / No credentials or provider settings reach this process, so a regression cannot spend real calls.
    offline = {k: v for k, v in os.environ.items()
               if not k.startswith(('GEMINI_', 'GLM_', 'BEDROCK_', 'AWS_', 'HTTP_PROXY', 'HTTPS_PROXY'))
               and k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy')}
    offline['AWS_CONFIG_FILE'] = offline['AWS_SHARED_CREDENTIALS_FILE'] = os.devnull
    excessive = subprocess.run([sys.executable, '-I', str(script), '--provider', 'gemini', '--provider', 'glm',
                               '--provider', 'bedrock', '--live'], capture_output=True, timeout=10, env=offline)
    assert excessive.returncode == 2  # 18 次呼叫在任何供應商設定或網路 I/O 前即拒絕。 / 18 calls rejected before any provider configuration/network I/O.


def test_larger_review_budget_is_bound_to_every_request_and_total_cap():
    report = runner.initial_report(['gemini'], ['B01', 'B02'], str(uuid.uuid4()), 1024)
    assert report['limits']['reserved_output_tokens'] == 2048
    assert report['limits']['timeout_seconds'] == 30
    score.validate_collection(report, report['plan'])
    report['output_tokens_per_review'] = 512
    with pytest.raises(ValueError, match='request binding|limits mismatch'):
        score.validate_collection(report)
    with pytest.raises(ValueError):
        runner.initial_report(['mock-review-a', 'mock-review-b'], list(bench.SUITES['injection']), str(uuid.uuid4()), 1024)


def test_parent_refuses_worker_success_when_benchmark_evaluation_is_invalid(tmp_path):
    report = runner.initial_report(['mock-review-a'], ['B01'], str(uuid.uuid4()))
    path = tmp_path / 'artifacts' / report['run_id'] / 'report.json'
    life.persist(path, report)
    prepare_run(tmp_path, report['run_id'], operation='model-smoke')
    assert asyncio.run(runner.run_worker(tmp_path, report['run_id'])) == 0
    corrupt = json.loads(path.read_text())
    corrupt['checks'][0]['case_sha256'] = '0' * 64
    life.persist(path, corrupt)
    data = life.finish(tmp_path, report['run_id'], providers=report['providers'], returncode=0, expected_report=report)
    assert data['status'] == 'INCOMPLETE' and data['code'] == 'EVALUATION_INVALID'
    assert data['analysis'] is None and data['cleanup']['completed']
