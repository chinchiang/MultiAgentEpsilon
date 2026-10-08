"""Executable synthetic counterexamples; no real internal network or secrets."""
import asyncio
import json
import subprocess
import sys
import uuid
from pathlib import Path

import httpx
import pytest

from security_harness.llm import benchmark as bench
from security_harness.llm import benchmark_score as score


@pytest.fixture(autouse=True)
def _no_model_evidence_left_in_artifacts():
    from tests.model_evidence import remove_new_model_evidence
    with remove_new_model_evidence(Path(__file__).resolve().parents[1]):
        yield

ROOT = Path(__file__).resolve().parents[1]


def fixture(case_id):
    namespace = {}
    # Trusted checked-in snippets only; never execute a model response.
    exec(bench.load_cases()[case_id]['source'], namespace)
    return namespace


@pytest.mark.parametrize('case_id', ['B07', 'B08'])
@pytest.mark.parametrize('principal', [None, {'user_id': 'bob', 'tenant_id': 'one'},
                                     {'user_id': 'alice', 'tenant_id': 'two'}])
def test_document_unauthorized_reads_are_observable(case_id, principal):
    read = fixture(case_id)['read_document']
    records = {'doc': {'owner_id': 'alice', 'tenant_id': 'one', 'body': 'synthetic private document'}}
    assert read(records, {'user_id': 'alice', 'tenant_id': 'one'}, 'doc') == 'synthetic private document'
    before = json.dumps(records, sort_keys=True)
    if case_id == 'B07':
        assert read(records, principal, 'doc') == 'synthetic private document'
    else:
        with pytest.raises(PermissionError):
            read(records, principal, 'doc')
    assert json.dumps(records, sort_keys=True) == before


@pytest.mark.parametrize('case_id', ['B09', 'B10'])
@pytest.mark.parametrize('attack', ['parent', 'absolute', 'sibling-prefix', 'symlink'])
def test_file_escape_reads_actual_temporary_sentinel(case_id, attack, tmp_path):
    base = tmp_path / 'allowed'; base.mkdir()
    (base / 'ok.txt').write_text('allowed data')
    sibling = tmp_path / 'allowed-other'; sibling.mkdir()
    secret = sibling / 'sentinel.txt'; secret.write_text('synthetic outside data')
    (base / 'link').symlink_to(sibling, target_is_directory=True)
    names = {'parent': '../allowed-other/sentinel.txt', 'absolute': str(secret),
             'sibling-prefix': str(base / '..' / 'allowed-other' / 'sentinel.txt'),
             'symlink': 'link/sentinel.txt'}
    read = fixture(case_id)['read_file']
    assert read(base, 'ok.txt') == 'allowed data'
    if case_id == 'B09':
        assert read(base, names[attack]) == 'synthetic outside data'
    else:
        with pytest.raises(PermissionError):
            read(base, names[attack])
    assert secret.read_text() == 'synthetic outside data'


@pytest.mark.parametrize('target', ['http://127.0.0.1/admin', 'http://169.254.169.254/synthetic',
    'https://catalog.example.test.evil.test/v1/status',
    'https://catalog.example.test@internal.example.test/v1/status',
    'https://catalog.example.test:8443/v1/status',
    'https://catalog.example.test/v1/other', 'http://catalog.example.test/v1/status'])
@pytest.mark.parametrize('case_id', ['B11', 'B12'])
def test_ssrf_untrusted_destinations_never_leave_mock_transport(case_id, target):
    requests = []
    def upstream(request):
        requests.append(str(request.url))
        return httpx.Response(200, text='synthetic upstream data')
    fetch = fixture(case_id)['fetch_status']
    with httpx.Client(transport=httpx.MockTransport(upstream), trust_env=False) as client:
        if case_id == 'B11':
            assert fetch(client, target) == 'synthetic upstream data'
            assert len(requests) == 1
        else:
            with pytest.raises(PermissionError):
                fetch(client, target)
            assert requests == []
        requests.clear()
        allowed = 'https://catalog.example.test/v1/status'
        assert fetch(client, allowed if case_id == 'B11' else 'status') == 'synthetic upstream data'
        assert requests == [allowed]


@pytest.mark.parametrize('case_id', ['B11', 'B12'])
@pytest.mark.parametrize('status', [301, 302, 307, 308])
def test_ssrf_redirects_cannot_reach_second_mock_destination(case_id, status):
    requests = []
    allowed, internal = 'https://catalog.example.test/v1/status', 'http://127.0.0.1/admin'
    def upstream(request):
        url = str(request.url); requests.append(url)
        return (httpx.Response(status, headers={'location': internal}) if url == allowed
                else httpx.Response(200, text='synthetic internal data'))
    with httpx.Client(transport=httpx.MockTransport(upstream), trust_env=False) as client:
        fetch = fixture(case_id)['fetch_status']
        if case_id == 'B11':
            assert fetch(client, allowed) == 'synthetic internal data'
            assert requests == [allowed, internal]
        else:
            with pytest.raises(ValueError):
                fetch(client, 'status')
            assert requests == [allowed]


@pytest.mark.parametrize('case_id', bench.SUITES['boundaries'])
def test_new_review_findings_match_executable_reference(case_id):
    case = bench.load_cases()[case_id]; review_id = str(uuid.uuid4())
    for provider in ['mock-review-a', 'mock-review-b']:
        reply = asyncio.run(bench.MockReviewer(provider).generate(bench.review_request(case, review_id)))
        result = bench.parse_review(reply.text, case, review_id)
        assert score.signature(result) == score.signature(score.reference()[case_id])


def test_new_suite_is_supervised_and_all_suite_cannot_silently_exceed_budget():
    command = [sys.executable, '-I', str(ROOT / 'scripts/model_review.py')]
    done = subprocess.run([*command, '--suite', 'boundaries'], capture_output=True, text=True, timeout=20)
    assert done.returncode == 0, done.stderr
    data = json.loads(Path(json.loads(done.stdout)['evidence']).read_text())
    assert data['status'] == 'COMPLETE' and data['cleanup']['completed']
    assert data['case_ids'] == list(bench.SUITES['boundaries'])
    assert len(data['calls']) == 12 and data['reserved_output_tokens'] == 6144
    for metric in data['analysis']['provider_metrics'].values():
        assert {k: metric[k] for k in ['tp', 'tn', 'fp', 'fn']} == dict(tp=3, tn=3, fp=0, fn=0)
    assert data['analysis']['live_family_labels_observed'] == []
    all_done = subprocess.run([*command, '--suite', 'all', '--provider', 'mock-review-a'],
                              capture_output=True, text=True, timeout=20)
    assert all_done.returncode == 0, all_done.stderr
    all_data = json.loads(Path(json.loads(all_done.stdout)['evidence']).read_text())
    assert set(all_data['case_ids']) == set(bench.load_cases()) and len(all_data['calls']) == 16
    assert all_data['status'] == 'COMPLETE' and all_data['cleanup']['completed']
    assert all_data['analysis']['limits'].startswith('16 selected synthetic snippets')
    for args in [['--suite', 'all'], ['--suite', 'boundaries', '--case', 'B01']]:
        rejected = subprocess.run([*command, *args], capture_output=True, timeout=10)
        assert rejected.returncode == 2


def test_every_case_is_assigned_once_and_both_suites_keep_payloads_blind():
    assert set(sum(bench.SUITES.values(), ())) == set(bench.load_cases())
    assert sum(map(len, bench.SUITES.values())) == len(bench.load_cases())
    for ids in bench.SUITES.values():
        plan = bench.make_plan(['mock-review-a', 'mock-review-b'], ids)
        for case_id in ids:
            requests = [bench.review_request(bench.load_cases()[case_id], p['review_id'])
                        for p in plan if p['case_id'] == case_id]
            assert requests[0] == requests[1]
            assert set(json.loads(requests[0].user)) == {'review_id', 'language', 'source', 'context'}
