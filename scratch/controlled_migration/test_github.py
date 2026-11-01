from copy import deepcopy
import pytest
from github_adapter import GitHubAdapter
from test_migration import PLAN, RULE


class Transport:
    def __init__(self):
        self.requests = []
        self.responses = {}
    def request(self, method, path, payload=None, **kwargs):
        self.requests.append((method, path, deepcopy(payload)))
        value = self.responses[(method, path)]
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)


def test_adapter_writes_only_pinned_rule_and_single_exact_head_merge():
    transport = Transport()
    transport.responses[('PUT', 'rulesets/24512048')] = {}
    transport.responses[('PUT', 'pulls/64/merge')] = {'merged': True}
    adapter = GitHubAdapter(transport, RULE)
    adapter.set_ruleset({**RULE, 'enforcement': 'disabled'})
    adapter.merge(PLAN['expected_head_sha'])
    assert transport.requests == [
        ('PUT', 'rulesets/24512048', {**RULE, 'enforcement': 'disabled'}),
        ('PUT', 'pulls/64/merge', {'sha': PLAN['expected_head_sha'], 'merge_method': 'merge'}),
    ]
    with pytest.raises(ValueError):
        adapter.merge('b' * 40)
    with pytest.raises(ValueError):
        adapter.set_ruleset({**RULE, 'bypass_actors': [{'actor_id': 1}]})


def test_cli_transport_cannot_write_without_execution_gate():
    from github_adapter import GhTransport
    calls = []
    transport = GhTransport(runner=lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError, match='WRITE_NOT_AUTHORIZED'):
        transport.request('PUT', 'rulesets/24512048', RULE)
    with pytest.raises(ValueError, match='DESTINATION'):
        transport.request('GET', 'https://example.com')
    assert calls == []

import io
import json
import zipfile
from migration import SCOPE


def archive(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as output:
        for name, value in files.items():
            output.writestr(name, json.dumps(value))
    return stream.getvalue()


class Repository(Transport):
    def items(self, path, key=None, **kwargs):
        return self.request('GET', path, **kwargs)


def repository():
    t = Repository()
    head, base = PLAN['expected_head_sha'], PLAN['expected_base_sha']
    repo = {'id': 123, 'full_name': SCOPE['repository']}
    pr = {'number': 64, 'state': 'open', 'draft': False, 'user': {'login': 'chinchiang'},
          'head': {'sha': head, 'ref': 'fix/certifi-2026.10.23', 'repo': repo},
          'base': {'sha': base, 'ref': 'main', 'repo': repo}}
    run = {'id': 100, 'run_attempt': 2, 'head_sha': head, 'head_branch': pr['head']['ref'],
           'head_repository': repo, 'repository': repo, 'event': 'pull_request_target',
           'path': '.github/workflows/security.yml', 'workflow_id': 20, 'status': 'completed',
           'actor': {'login': 'chinchiang'}, 'triggering_actor': {'login': 'chinchiang'}, 'pull_requests': []}
    guard = {'schema_version': 2, 'base_sha': base, 'candidate_sha': head, 'decision': 'ALLOW',
             'baseline_approval': {'review_id': 5, 'reviewer': 'd98922036ntu', 'commit_id': head}}
    provenance = {'schema_version': 1, 'repository': SCOPE['repository'], 'repository_id': 123,
                  'run_id': 100, 'run_attempt': 2, 'event': 'pull_request_target',
                  'workflow_sha': base, 'base_sha': base, 'candidate_sha': head, 'pr_number': 64,
                  'workflow_ref': SCOPE['repository']+'/.github/workflows/security.yml@refs/heads/main'}
    values = {
        'user': {'login': 'chinchiang'}, 'collaborators/chinchiang/permission': {'permission': 'admin'},
        'branches/main': {'commit': {'sha': base}}, 'pulls/64': pr, 'rulesets/24512048': RULE,
        'rulesets?includes_parents=true': [{'id': 24512048, 'enforcement': 'active'}],
        'branches/main/protection': None,
        f'compare/{base}...{head}': {'files': [{'filename': 'requirements.lock', 'status': 'modified',
                                               'sha': 'e428ccd6d661fdd0188dcdf3530e5a7846c3acd4'}]},
        'pulls/64/reviews': [{'id': 5, 'state': 'APPROVED', 'commit_id': head, 'user': {'login': 'd98922036ntu'}}],
        'collaborators/d98922036ntu/permission': {'permission': 'write'},
        'pulls/64/commits': [{'sha': head, 'author': {'login': 'chinchiang'}, 'committer': {'login': 'chinchiang'}}],
        f'actions/workflows/security.yml/runs?event=pull_request_target&head_sha={head}': [run],
        'actions/workflows/security.yml': {'id': 20, 'path': '.github/workflows/security.yml'},
        'pulls?state=all&head=chinchiang:fix/certifi-2026.10.23': [pr],
        'issues/64/timeline': [],
        'actions/runs/100/attempts/2/jobs': [{'name': 'trusted-security-evaluation', 'run_id': 100, 'run_attempt': 2,
                                           'steps': [{'name': 'Check protected changes and exact-head independent approval', 'conclusion': 'success'}]}],
        'actions/runs/100/artifacts': [{'id': 7, 'name': 'trusted-security-100-2', 'expired': False}],
        'actions/artifacts/7/zip': archive({'audit/trusted-guard.json': guard, 'audit/ci-provenance.json': provenance}),
    }
    t.responses.update({('GET', k): v for k, v in values.items()})
    return t


def test_adapter_derives_preconditions_from_remote_source_evidence():
    adapter = GitHubAdapter(repository(), RULE)
    snapshot = adapter.observe()
    assert snapshot['review_valid'] is True
    assert snapshot['guard_valid'] is True
    assert snapshot['only_expected_lock_diff'] is True
    assert snapshot['expected_head_sha'] == 'f7e424b47fed9e4a27d10b2f73b3a6e3278508b7'


@pytest.mark.parametrize('path,value', [
    ('branches/main', {'commit': {'sha': 'b'*40}}),
    ('collaborators/chinchiang/permission', {'permission': 'write'}),
    ('rulesets?includes_parents=true', [{'id': 24512048}, {'id': 1}]),
    ('branches/main/protection', {'required_status_checks': {}}),
    ('issues/64/timeline', [{'event': 'base_ref_changed'}]),
    ('pulls/64/reviews', [{'id': 5, 'state': 'DISMISSED', 'commit_id': PLAN['expected_head_sha'], 'user': {'login': 'd98922036ntu'}}]),
])
def test_adapter_rejects_untrusted_or_changed_preconditions(path, value):
    transport = repository()
    transport.responses[('GET', path)] = value
    with pytest.raises(ValueError):
        GitHubAdapter(transport, RULE).observe()
    assert all(method == 'GET' for method, _, _ in transport.requests)


def merged_repository():
    transport = repository()
    sha = 'a' * 40
    transport.responses[('GET', 'pulls/64')] = {'merged': True, 'merge_commit_sha': sha}
    transport.responses[('GET', 'commits/'+sha)] = {'parents': [{'sha': PLAN['expected_base_sha']}, {'sha': PLAN['expected_head_sha']}]}
    transport.responses[('GET', f"compare/{PLAN['expected_base_sha']}...{sha}")] = {'files': [
        {'filename': 'requirements.lock', 'status': 'modified', 'sha': 'e428ccd6d661fdd0188dcdf3530e5a7846c3acd4'}]}
    transport.responses[('GET', f'actions/workflows/security.yml/runs?event=push&head_sha={sha}')] = [
        {'id': 200, 'run_attempt': 1, 'event': 'push', 'head_sha': sha, 'head_branch': 'main',
         'path': '.github/workflows/security.yml', 'workflow_id': 20, 'status': 'completed', 'conclusion': 'success',
         'repository': {'full_name': SCOPE['repository']}}]
    transport.responses[('GET', 'actions/runs/200/attempts/1/jobs')] = [
        {'name': name, 'conclusion': 'success', 'run_id': 200, 'run_attempt': 1}
        for name in ['trusted-security-evaluation', 'trusted-mutation-tests', 'Attest evaluator-owned evidence', 'trusted-security-pilot']]
    provenance = {'event': 'push', 'workflow_sha': sha, 'base_sha': sha, 'candidate_sha': sha,
                  'run_id': 200, 'run_attempt': 1, 'repository': SCOPE['repository'],
                  'workflow_ref': SCOPE['repository']+'/.github/workflows/security.yml@refs/heads/main'}
    transport.responses[('GET', 'actions/runs/200/artifacts')] = [
        {'name': 'trusted-security-200-1', 'id': 8, 'expired': False},
        {'name': 'trusted-mutations-200-1', 'id': 9, 'expired': False}]
    transport.responses[('GET', 'actions/artifacts/8/zip')] = archive({'audit/ci-provenance.json': provenance})
    transport.responses[('GET', 'actions/artifacts/9/zip')] = archive({'trusted/artifacts/m/report.json': json.loads((__import__('pathlib').Path(__file__).with_name('mutation-success.fixture.json')).read_text())})
    transport.verify_attestation = lambda raw, run, sha: True
    return transport


def test_adapter_verifies_merged_content_and_formal_push_evidence():
    outcome = GitHubAdapter(merged_repository(), RULE).inspect_outcome()
    assert outcome['formal_push_ci'] == 'success'
    assert outcome['full_mutation'] == 'success'
    assert outcome['signature'] == 'success'
    assert outcome['parents'] == [PLAN['expected_base_sha'], PLAN['expected_head_sha']]


@pytest.mark.parametrize('sha_ok,invocation_ok,expected', [(True, True, True), (False, True, False), (True, False, False)])
def test_signature_verifier_binds_verified_statement_to_exact_commit_and_attempt(sha_ok, invocation_ok, expected):
    import hashlib
    from github_adapter import GhTransport
    raw = b'signed artifact bytes'
    sha = 'a' * 40
    proof = [{'verificationResult': {'statement': {
        'predicateType': 'https://slsa.dev/provenance/v1',
        'subject': [{'digest': {'sha256': hashlib.sha256(raw).hexdigest()}}],
        'predicate': {
            'buildDefinition': {'resolvedDependencies': [{'uri': 'git+https://github.com/chinchiang/MultiAgentEpsilon@refs/heads/main', 'digest': {'gitCommit': sha if sha_ok else 'b'*40}}]},
            'runDetails': {'metadata': {'invocationId':
                'https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/200/attempts/' + ('1' if invocation_ok else '2')}}}}}}]
    commands = []
    def runner(command, payload, **kwargs):
        commands.append(command)
        if 'api' in command:
            return json.dumps({'attestations': [{'bundle': {'test': 'bundle'}}]}).encode()
        assert '--cert-identity' in command
        assert '--deny-self-hosted-runners' in command
        assert '--bundle' in command
        return json.dumps(proof).encode()
    transport = GhTransport(runner=runner)
    if expected:
        assert transport.verify_attestation(raw, {'id': 200, 'run_attempt': 1}, sha) is True
    else:
        with pytest.raises(ValueError, match='ATTESTATION_BINDING'):
            transport.verify_attestation(raw, {'id': 200, 'run_attempt': 1}, sha)


def test_invalid_cryptographic_proof_is_failed_acceptance():
    transport = merged_repository()
    transport.verify_attestation = lambda *args: False
    outcome = GitHubAdapter(transport, RULE).inspect_outcome()
    assert outcome['signature'] == 'failure'


def test_mutation_report_must_include_full_campaign_and_cleanup():
    transport = merged_repository()
    value = json.loads(zipfile.ZipFile(io.BytesIO(transport.responses[('GET', 'actions/artifacts/9/zip')])).read('trusted/artifacts/m/report.json'))
    value['cleanup_completed'] = False
    transport.responses[('GET', 'actions/artifacts/9/zip')] = archive({'trusted/artifacts/m/report.json': value})
    outcome = GitHubAdapter(transport, RULE).inspect_outcome()
    assert outcome['full_mutation'] == 'failure'


@pytest.mark.parametrize('status,body,allowed', [
    (404, {'message': 'Branch not protected'}, True),
    (404, {'message': 'Not Found'}, False),
    (401, {'message': 'Requires authentication'}, False),
])
def test_only_explicit_absent_legacy_protection_is_accepted(status, body, allowed):
    from github_adapter import GhTransport
    response = f'HTTP/2 {status}\r\nContent-Type: application/json\r\n\r\n'.encode()+json.dumps(body).encode()
    transport = GhTransport(runner=lambda *args, **kwargs: response)
    if allowed:
        assert transport.request('GET', 'branches/main/protection', allow_404=True) is None
    else:
        with pytest.raises(ValueError):
            transport.request('GET', 'branches/main/protection', allow_404=True)


def test_incomplete_paginated_listing_cannot_supply_success_evidence():
    from github_adapter import GhTransport
    transport = GhTransport(runner=lambda *args, **kwargs: b'{"total_count":2,"jobs":[{"id":1}]}')
    with pytest.raises(ValueError, match='PAGINATION_TOTAL'):
        transport.items('actions/runs/200/jobs', key='jobs')


def test_transport_saves_raw_evidence_without_credential_values(tmp_path):
    from runtime import Journal
    from github_adapter import GhTransport
    journal = Journal(tmp_path/'evidence')
    transport = GhTransport(evidence=journal, runner=lambda *args, **kwargs: b'{"id":24512048}')
    assert transport.request('GET', 'rulesets/24512048') == {'id': 24512048}
    events = [json.loads(line) for line in journal.path.read_text().splitlines()]
    record = next(event for event in events if event['event'] == 'github_response')
    assert record['path'] == 'rulesets/24512048'
    assert json.loads((journal.directory/record['file']).read_bytes()) == {'id': 24512048}


def test_recovery_readback_survives_exhausted_ordinary_read_budget():
    from github_adapter import GhTransport
    calls = []
    def runner(command, payload, **kwargs):
        calls.append(command)
        return json.dumps(RULE).encode()
    transport = GhTransport(write_enabled=True, runner=runner)
    adapter = GitHubAdapter(transport, RULE)
    for _ in range(1500):
        transport.request('GET', 'user')
    with pytest.raises(ValueError, match='READ_BUDGET'):
        transport.request('GET', 'user')
    adapter.set_ruleset(RULE)
    assert adapter.read_ruleset(recovery=True) == RULE
    assert len(calls) == 1502
    with pytest.raises(ValueError, match='READ_BUDGET'):
        adapter.read_ruleset()


def test_slow_post_disable_evidence_reads_restore_at_shared_deadline():
    from github_adapter import GhTransport
    from migration import run
    from test_migration import Clock, consent
    from urllib.parse import urlsplit, parse_qsl, urlencode
    clock = Clock()
    data = repository().responses
    reads, restores, merge_requests = [], [], []
    prefix = 'repos/chinchiang/MultiAgentEpsilon/'
    def runner(command, payload, **kwargs):
        method = command[command.index('--method')+1]
        endpoint = next(arg for arg in command if arg.startswith(prefix) or arg == 'user')
        path = endpoint.removeprefix(prefix)
        parts = urlsplit(path)
        query = [(k, v) for k, v in parse_qsl(parts.query) if k not in ('per_page', 'page')]
        path = parts.path + ('?'+urlencode(query, safe=':/') if query else '')
        rule_key = ('GET', 'rulesets/24512048')
        if method == 'PUT':
            value = json.loads(payload)
            if path == 'rulesets/24512048':
                data[rule_key] = value
                if value['enforcement'] == 'active':
                    restores.append(clock.monotonic())
            elif path == 'pulls/64/merge':
                merge_requests.append(value)
            return b'{}'
        if data[rule_key]['enforcement'] == 'disabled':
            reads.append({'time': clock.monotonic(), 'timeout': kwargs['timeout']})
            clock.seconds += min(11, kwargs['timeout'])
        value = data[(method, path)]
        if path == 'branches/main/protection':
            return b'HTTP/2 404\r\n\r\n{"message":"Branch not protected"}'
        if isinstance(value, bytes):
            return value
        if isinstance(value, list):
            key = 'workflow_runs' if '/runs?' in path else 'jobs' if path.endswith('/jobs') else 'artifacts' if path.endswith('/artifacts') else None
            if key:
                value = {'total_count': len(value), key: value}
        return json.dumps(value).encode()
    adapter = GitHubAdapter(GhTransport(write_enabled=True, runner=runner), RULE)
    result = run(PLAN, adapter, execute=True, authorization=consent(), clock=clock)
    assert result['restored'] is True
    assert result['accepted'] is False
    assert restores == [60]
    assert reads and all(read['time'] < 60 for read in reads)
    assert reads[-1]['timeout'] == 5
    assert merge_requests == []


@pytest.mark.parametrize('operation', ['pagination', 'artifact'])
def test_shared_deadline_bounds_pagination_and_artifact_download(operation):
    from github_adapter import GhTransport
    from test_migration import Clock
    clock = Clock()
    clock.seconds = 55
    timeouts = []
    def runner(command, payload, **kwargs):
        timeouts.append(kwargs['timeout'])
        clock.seconds += min(4, kwargs['timeout'])
        return json.dumps([{'id': i} for i in range(100)]).encode() if operation == 'pagination' else b'archive'
    transport = GhTransport(runner=runner)
    if operation == 'pagination':
        with pytest.raises(TimeoutError, match='MERGE_WINDOW_EXPIRED'):
            transport.items('pulls/64/reviews', deadline=60, clock=clock)
        assert timeouts == [5, 1]
    else:
        assert transport.request('GET', 'actions/artifacts/8/zip', binary=True, deadline=60, clock=clock) == b'archive'
        with pytest.raises(TimeoutError, match='MERGE_WINDOW_EXPIRED'):
            transport.request('GET', 'actions/artifacts/9/zip', binary=True, deadline=60, clock=clock)
        assert timeouts == [5, 1]
    assert clock.monotonic() == 60
    with pytest.raises(TimeoutError):
        transport.request('GET', 'user', deadline=60, clock=clock)
    assert timeouts == [5, 1]


@pytest.mark.parametrize('method,path', [('GET', 'user'), ('GET', 'pulls/64'), ('PUT', 'rulesets/24512048')])
def test_recovery_budget_exemption_is_limited_to_exact_ruleset_get(method, path):
    from github_adapter import GhTransport
    calls = []
    transport = GhTransport(write_enabled=True, runner=lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match='RECOVERY_READ_SCOPE'):
        transport.request(method, path, recovery=True)
    assert calls == []
