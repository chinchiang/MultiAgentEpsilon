"""Regressions for the reported trust, recovery, coverage and accounting attacks."""
import asyncio
import copy
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from security_harness import lifecycle, trusted_publisher as publisher
from security_harness.audit import AuditRun
from security_harness.llm import benchmark as bench, benchmark_score as score
from security_harness.llm.gateway import Gateway, Limits, Request
from security_harness.results import executable_bits, write_json
from tests.test_trusted_publisher import bundle
from tests.test_model_benchmark import collected


@pytest.mark.parametrize('events', [None, {}, {5: None}, {5: [{}]},
    {5: [{'event': 'base_ref_changed'}]},
    {5: [{'event': 'base_ref_changed'}, {'event': 'base_ref_changed'}]}])
def test_missing_or_retargeted_base_history_is_never_trusted(bundle, events):
    with pytest.raises(publisher.Denied, match='BASE_HISTORY|BASE_RETARGETED'):
        publisher.validate_run_base(bundle['run'], bundle['pr'], [bundle['pr']], 'main', events)


@pytest.mark.parametrize('changed', ['repo', 'branch'])
def test_same_sha_in_another_fork_or_branch_cannot_block_source_binding(bundle, changed):
    other = copy.deepcopy(bundle['pr'])
    other['number'] = 6
    other['base']['ref'] = 'untrusted'
    if changed == 'repo': other['head']['repo']['id'] = 20
    else: other['head']['ref'] = 'other'
    publisher.validate_run_base(bundle['run'], bundle['pr'], [bundle['pr'], other], 'main', {5: []})
    newer = copy.deepcopy(bundle['run'])
    newer['id'] += 1
    if changed == 'repo': newer['head_repository']['id'] = 20
    else: newer['head_branch'] = 'other'
    publisher.reject_newer_runs(bundle['run'], [newer], bundle['pr']['head']['sha'])


@pytest.mark.parametrize('role,blocked', [('write', True), ('maintain', True), ('admin', True),
                                        ('read', False), ('triage', False), ('custom', True)])
def test_another_reviewer_requesting_changes_is_not_ignored(bundle, role, blocked):
    reviews = bundle['reviews'] + [{'id': 12, 'state': 'CHANGES_REQUESTED',
        'commit_id': bundle['pr']['head']['sha'], 'user': {'login': 'other'}}]
    permissions = {**bundle['permissions'], 'other': role}
    from scripts.check_trusted_changes import approved_review
    approval = approved_review(bundle['pr'], reviews, bundle['pr']['head']['sha'],
        bundle['pr']['base']['sha'], ['reviewer'], permissions)
    assert (approval is None) is blocked


def test_rerun_actor_cannot_approve_their_own_evaluation(bundle):
    from scripts.check_trusted_changes import approved_review
    assert approved_review(bundle['pr'], bundle['reviews'], bundle['pr']['head']['sha'],
        bundle['pr']['base']['sha'], ['reviewer'], bundle['permissions'], {'reviewer'}) is None


@pytest.mark.parametrize('amount', [1000, 10000, 10001])
def test_pagination_proves_completeness_at_full_page_boundaries(amount):
    client = publisher.GitHub('synthetic')
    def page(path):
        start = (int(path.rsplit('page=', 1)[1]) - 1) * 100
        return list(range(start, min(start + 100, amount)))
    client.api = page
    if amount > 10000:
        with pytest.raises(publisher.Denied, match='PAGINATION_LIMIT'): client.pages('/synthetic')
    else:
        assert client.pages('/synthetic') == list(range(amount))


@pytest.mark.parametrize('field', ['reserved_calls', 'reserved_output_tokens', 'model_roe_sha256',
                                  'max_calls', 'reserved_limit', 'timeout_seconds', 'total_timeout_seconds'])
def test_budget_and_rules_of_engagement_tampering_cannot_be_scored_complete(tmp_path, field):
    report, _ = collected(tmp_path)
    if field in ('max_calls', 'timeout_seconds'): report['limits'][field] += 1
    elif field == 'reserved_limit': report['limits']['reserved_output_tokens'] += 1
    elif field == 'model_roe_sha256': report[field] = '0' * 64
    else: report[field] += 1
    with pytest.raises(ValueError): score.summarize(report)


def test_successful_calls_cannot_erase_their_reservations(tmp_path):
    report, _ = collected(tmp_path)
    for call in report['calls']: call.update(reserved=False, reserved_output_tokens=0)
    report.update(reserved_calls=0, reserved_output_tokens=0)
    with pytest.raises(ValueError, match='reservation'): score.summarize(report)


def test_crash_after_request_delivery_keeps_durable_reservations(tmp_path):
    root = Path(__file__).resolve().parents[1]
    driver = tmp_path / 'driver.py'
    report = tmp_path / 'report.json'
    driver.write_text('''import asyncio,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from security_harness.llm.gateway import Gateway,Limits,Request
from security_harness.results import write_json
class Adapter:
 provider='mock'; family='mock'; model='synthetic'
 async def generate(self,request):
  Path(sys.argv[3]).write_text('delivered')
  await asyncio.Event().wait()
gateway=Gateway(Limits(max_calls=1,reserved_output_tokens=512))
def checkpoint():
 write_json(Path(sys.argv[2]),dict(calls=gateway.evidence,reserved_calls=gateway.calls,reserved_output_tokens=gateway.reserved_tokens))
gateway.checkpoint=checkpoint
asyncio.run(gateway.generate(Adapter(),Request(system='Synthetic',user='Synthetic',max_output_tokens=512)))
''')
    process = subprocess.Popen([sys.executable, str(driver), str(root), str(report), str(tmp_path / 'delivered')])
    try:
        deadline = time.monotonic() + 5
        while not (tmp_path / 'delivered').exists() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(.02)
        assert (tmp_path / 'delivered').exists()
        process.kill(); process.wait(timeout=5)
        data = json.loads(report.read_text())
        assert data['reserved_calls'] == 1 and data['reserved_output_tokens'] == 512
        assert data['calls'][0]['status'] == 'IN_FLIGHT'
        assert data['calls'][0]['reserved'] is True
        assert data['calls'][0]['output_tokens'] is None
    finally:
        if process.poll() is None: process.kill(); process.wait(timeout=5)


def test_core_janitor_does_not_signal_a_reused_pid_after_reboot(tmp_path, monkeypatch):
    audit = AuditRun(tmp_path, 'security')
    work = lifecycle.prepare_run(tmp_path, audit.data['run_id'])
    marker = json.loads((work / 'owner.json').read_text())
    marker.update(boot='earlier-boot', worker_pid=os.getpid(), worker_start=lifecycle.identity(os.getpid()))
    write_json(work / 'owner.json', marker)
    monkeypatch.setattr(lifecycle, 'terminate_group', lambda pid: pytest.fail('must not signal another boot'))
    from security_harness import isolation
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    assert lifecycle.sweep_stale(tmp_path) == [audit.data['run_id']]
    data = json.loads((audit.output / 'report.json').read_text())
    assert data['cleanup']['completed'] and data['cleanup']['boot_changed']


@pytest.mark.parametrize('mode,expected', [(0o700, 0o111), (0o710, 0o111), (0o744, 0o111),
                                        (0o755, 0o111), (0o640, 0), (0o650, 0)])
def test_manifest_modes_follow_git_owner_execute_semantics(mode, expected):
    assert executable_bits(mode) == expected


@pytest.mark.parametrize('location', ['message', 'author', 'committer', 'tag-name', 'tag-body'])
def test_git_metadata_secrets_are_scanned_and_redacted(tmp_path, location):
    from tests.test_gitleaks import run
    canary = 'VIBE_TEST_' + 'SECRET_' + secrets.token_hex(16)
    def git(*args):
        return subprocess.run(['git', '-C', str(tmp_path), *args], check=True, capture_output=True)
    git('init', '-q')
    git('config', 'user.name', canary if location == 'committer' else 'Synthetic')
    git('config', 'user.email', 'synthetic@example.invalid')
    (tmp_path / 'ordinary.txt').write_text('No secrets in any file.\n')
    git('add', '.')
    args = ['commit', '-qm', canary if location == 'message' else 'synthetic']
    if location == 'author': args += ['--author', canary + ' <synthetic@example.invalid>']
    git(*args)
    if location == 'tag-name': git('tag', canary)
    if location == 'tag-body': git('tag', '-a', 'synthetic', '-m', canary)
    report = run(tmp_path, history=True)
    assert any(f['scope'] == 'history-metadata' for f in report['findings'])
    assert canary not in json.dumps(report)


@pytest.mark.parametrize('codepoint', [0x034f, 0x3164, 0x2800, 0xfe00, 0xfe0f, 0xe0100, 0xe01ef])
def test_invisible_review_text_is_rejected(codepoint):
    from tests.test_model_benchmark import review_value
    case, token, value = review_value()
    value['reason'] += chr(codepoint)
    with pytest.raises(Exception): bench.parse_review(json.dumps(value), case, token)


def test_all_contexts_avoid_per_case_answer_category_hints():
    for case in bench.load_cases().values():
        context = case['context'].lower()
        assert 'assess only' not in context and 'only assess' not in context and 'cwe-' not in context


def test_unknown_provider_is_a_configuration_error(monkeypatch):
    from scripts.model_smoke import configured_adapter
    from security_harness.llm.gateway import ModelError
    monkeypatch.delenv('BEDROCK_MODEL_ID', raising=False)
    with pytest.raises(ModelError) as failure: configured_adapter('typo')
    assert failure.value.code == 'CONFIGURATION'


def test_missing_aws_cli_blocks_before_call_reservation(monkeypatch):
    from scripts.model_smoke import configured_adapter
    from security_harness.llm.gateway import ModelError
    monkeypatch.setenv('AWS_CLI_PATH', '/nonexistent/synthetic-aws')
    with pytest.raises(ModelError) as failure: configured_adapter('bedrock')
    assert failure.value.code == 'CONFIGURATION'


@pytest.mark.parametrize('field', ['invocation', 'digest', 'predicate', 'missing', 'nonzero'])
def test_attestation_verifier_rejects_forged_or_wrong_run_proofs(tmp_path, monkeypatch, bundle, field):
    from security_harness import processes
    from scripts import publish_trusted_check
    binary = tmp_path / 'gh'
    binary.write_bytes(b'approved-test-verifier'); binary.chmod(0o755)
    settings, run = bundle['settings'], bundle['run']
    settings.update(attestation_verifier=str(binary),
                    attestation_verifier_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    monkeypatch.setattr(publish_trusted_check, 'open_config', lambda path, owner: os.open(path, os.O_RDONLY))
    original_stat = os.fstat
    def trusted_stat(fd):
        info = original_stat(fd)
        values = list(info)
        values[4] = 0
        return os.stat_result(values)
    monkeypatch.setattr(publisher.os, 'fstat', trusted_stat)
    raw = b'evaluator artifact'
    statement = {'predicateType': 'https://slsa.dev/provenance/v1',
        'subject': [{'digest': {'sha256': hashlib.sha256(raw).hexdigest()}}],
        'predicate': {'runDetails': {'metadata': {'invocationId':
            'https://github.com/owner/repo/actions/runs/100/attempts/1'}}}}
    if field == 'invocation': statement['predicate']['runDetails']['metadata']['invocationId'] += '0'
    if field == 'digest': statement['subject'][0]['digest']['sha256'] = '0'*64
    if field == 'predicate': statement['predicateType'] = 'untrusted'
    def verify(command, payload, **kwargs):
        assert command[1:3] == ['attestation', 'verify']
        for flag in ('--signer-workflow', '--signer-digest', '--source-ref', '--deny-self-hosted-runners', '--bundle'):
            assert flag in command
        assert command[command.index('--signer-digest') + 1] == settings['evaluator_sha']
        assert not any(k.startswith(('AWS_', 'GEMINI_', 'GLM_', 'BEDROCK_', 'GH_TOKEN')) for k in kwargs['env'])
        assert kwargs['env']['XDG_CACHE_HOME'].startswith('/tmp/epsilon-attestation-')
        if field == 'nonzero': raise RuntimeError('invalid cryptographic signature')
        return json.dumps([] if field == 'missing' else [{'verificationResult': {'statement': statement}}]).encode()
    monkeypatch.setattr(processes, 'bounded_output', verify)
    class Client:
        def api(self, path):
            assert '/attestations/sha256:' in path
            return {'attestations': [{'bundle': {'synthetic': 'unsigned input'}}]}
    with pytest.raises(publisher.Denied, match='ATTESTATION_'):
        publisher.verify_artifact_attestation(Client(), settings, run, raw)


@pytest.mark.parametrize('status,headers,code', [(403, {}, 'GITHUB_HTTP_403'),
    (403, {'X-RateLimit-Remaining': '0'}, 'GITHUB_RATE_LIMIT'),
    (403, {'Retry-After': '60'}, 'GITHUB_RATE_LIMIT'), (429, {}, 'GITHUB_RATE_LIMIT')])
def test_permission_errors_and_throttling_are_distinct(status, headers, code):
    import urllib.error
    client = publisher.GitHub('synthetic')
    def fail(*args, **kwargs):
        raise urllib.error.HTTPError('https://api.github.com/synthetic', status, 'synthetic', headers, None)
    client.opener.open = fail
    with pytest.raises(publisher.Denied, match=code): client.api('/synthetic')


def test_rate_limit_before_first_pr_lookup_persists_backoff(bundle):
    class Client:
        def api(self, path): raise publisher.Denied('GITHUB_RATE_LIMIT')
    state = {}
    with pytest.raises(publisher.Denied, match='GITHUB_RATE_LIMIT'):
        publisher.publish(Client(), bundle['settings'], bundle['gate_policy'], 5, state=state)
    assert state['backoff_until'] > time.time()


@pytest.mark.parametrize('provider', ['bedrock', 'gemini'])
def test_provider_schema_bounds_match_supported_keywords(provider):
    from security_harness.llm.output_schema import request_schema
    request = bench.review_request(bench.load_cases()['B09'], 'opaque-id')
    schema = request_schema(request, provider)
    findings = schema['properties']['findings']
    line = findings['items']['properties']['line']
    assert findings['maxItems'] == 3
    count = len(bench.load_cases()['B09']['source'].splitlines())
    if provider == 'bedrock':
        assert line['enum'] == list(range(1, count + 1))
        assert not any(keyword in json.dumps(schema) for keyword in ('minimum', 'maximum', 'minLength', 'maxLength'))
    else: assert line['minimum'] == 1 and line['maximum'] == count


def test_core_worker_cannot_execute_before_durable_registration(tmp_path, monkeypatch):
    from security_harness import isolation
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    audit = AuditRun(tmp_path, 'security')
    original_write = lifecycle.write_json
    def fail_registration(path, value):
        if path.name == 'owner.json' and 'worker_pid' in value: raise OSError('synthetic registration failure')
        original_write(path, value)
    monkeypatch.setattr(lifecycle, 'write_json', fail_registration)
    command = [sys.executable, '-c', 'from pathlib import Path; Path("executed").write_text("unsafe")']
    assert lifecycle.supervise(tmp_path, audit, command, 5) == 1
    assert not (tmp_path / 'executed').exists()
    assert audit.data['decision'] == 'BLOCK' and audit.data['cleanup']['completed']


@pytest.mark.parametrize('attack', ['archive', 'binary', 'symlink'])
def test_verifier_installer_rejects_bad_digest_and_nonfile_entries(attack):
    import io
    import tarfile
    from scripts.install_attestation_verifier import verified_binary
    content = b'synthetic verifier'
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        item = tarfile.TarInfo('gh_1.0.0_linux_amd64/bin/gh')
        if attack == 'symlink': item.type = tarfile.SYMTYPE; item.linkname = '/untrusted'
        else: item.size = len(content)
        archive.addfile(item, io.BytesIO(content) if attack != 'symlink' else None)
    body = stream.getvalue()
    pin = {'version': '1.0.0', 'archive_sha256': hashlib.sha256(body).hexdigest(),
           'binary_sha256': hashlib.sha256(content).hexdigest()}
    if attack == 'archive': pin['archive_sha256'] = '0'*64
    if attack == 'binary': pin['binary_sha256'] = '0'*64
    with pytest.raises(ValueError): verified_binary(body, pin)


@pytest.mark.parametrize('name', ['../outside', '/outside', 'aws\\outside'])
def test_aws_installer_refuses_archive_path_escape(tmp_path, name):
    import io
    import zipfile
    from scripts.install_aws_cli import unpack
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive: archive.writestr(name, 'synthetic')
    body = stream.getvalue()
    with pytest.raises(ValueError, match='AWS_ARCHIVE_ENTRY'):
        unpack(body, {'archive_sha256': hashlib.sha256(body).hexdigest()}, tmp_path)


def test_unsigned_adjudication_consumer_refuses_notes_for_changed_report(tmp_path):
    report, path = collected(tmp_path)
    note = score.add_adjudication(path, report['case_ids'][0], 'NEEDS_MORE_EVIDENCE', 'Synthetic', 'Review pending.')
    assert score.read_adjudications(path)[0]['identity_verified'] is False
    path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(ValueError, match='stale'): score.read_adjudications(path)


def test_separate_trusted_and_application_seeds_keep_the_same_fixture_contract(monkeypatch):
    from fixture_app import app
    from security_harness import fixture_database as oracle
    records = []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def execute(self, query, params=None):
            records.append((query if isinstance(query, str) else query.as_string(None), params))
    monkeypatch.setattr(app, 'connect', lambda *args: Connection())
    monkeypatch.setattr(oracle, 'connect', lambda *args: Connection())
    monkeypatch.setattr(secrets, 'token_hex', lambda size: 'a' * (size * 2))
    monkeypatch.setattr(secrets, 'token_urlsafe', lambda size: 'synthetic-password')
    first = app.seed('synthetic'); expected = records.copy(); records.clear()
    second = oracle.seed('synthetic')
    assert first == second and records == expected


def test_changed_base_image_pin_blocks_before_any_candidate_or_container_use(tmp_path, monkeypatch):
    from security_harness import isolation
    (tmp_path / '.state').mkdir()
    (tmp_path / 'security').mkdir()
    write_json(tmp_path / '.state/runtime-image.json', {'base_image': 'old-pin'})
    write_json(tmp_path / 'security/tools.lock.json', {'python_runtime': {'image': 'new-pin'}})
    monkeypatch.setattr(isolation, 'ROOT', tmp_path)
    monkeypatch.setattr(isolation, 'docker', lambda *args, **kwargs: pytest.fail('stale runtime must not launch'))
    with pytest.raises(ValueError, match='base image is stale'): isolation.run_isolated(tmp_path / 'unused-candidate')


@pytest.mark.parametrize('owners,expected', [('* @reviewer\nsecurity/* @other', []),
    ('* @reviewer @other\nsecurity/* @reviewer', ['reviewer']),
    ('* @reviewer\nsecurity/*', []), ('* @reviewer\n* @other', ['other'])])
def test_scoped_codeowner_rules_cannot_claim_an_unlisted_person_owns_every_path(owners, expected):
    from scripts.audit_merge_protection import codeowners_reviewers
    assert codeowners_reviewers(owners) == expected


def test_full_guard_fetches_and_excludes_the_rerun_actor(bundle, monkeypatch):
    from scripts import check_trusted_changes as guard
    reviewer = 'CatGrocery'
    bundle['reviews'][0]['user']['login'] = reviewer
    bundle['run']['triggering_actor']['login'] = reviewer
    monkeypatch.setenv('GITHUB_RUN_ID', '100')
    paths = []
    def api(args, **kwargs):
        path = args[2].split('/', 3)[3]; paths.append(path)
        paged = '--paginate' in args
        if path == 'pulls/5': value = bundle['pr']
        elif '/reviews?' in path: value = bundle['reviews']
        elif '/commits?' in path: value = [{'sha': 'b'*40, 'author': {'login': 'author'}, 'committer': None}]
        elif path.startswith('collaborators/'): value = {'role_name': 'write'}
        elif path.startswith('commits/'): value = {'author': {'login': 'author'}, 'committer': None}
        elif path == 'actions/runs/100': value = bundle['run']
        elif path.startswith('pulls?state=all&head='): value = [bundle['pr']]
        elif '/timeline?' in path: value = []
        else: pytest.fail('unexpected API ' + path)
        return ''.join(json.dumps(v)+'\n' for v in value) if paged else json.dumps(value)
    monkeypatch.setattr(guard.subprocess, 'check_output', api)
    assert guard.live_approval(5, 'b'*40, 'a'*40) is None
    assert 'actions/runs/100' in paths and any('/timeline?' in p for p in paths)


def test_glm_blind_review_worker_scoring_and_cleanup_use_mock_transport_only(tmp_path, monkeypatch):
    import httpx
    from scripts import model_smoke
    from security_harness.llm.adapters import GLMAdapter
    from security_harness.llm.transport import JsonHTTP
    from security_harness.llm.gateway import Request
    from tests.test_model_gateway import Bytes
    async def handler(request):
        payload = json.loads(request.content)
        messages = payload['messages']
        model_request = Request(messages[0]['content'], messages[1]['content'],
                                max_output_tokens=payload['max_tokens'], response_format='security-review-json-v1')
        response = await bench.MockReviewer('mock-review-a').generate(model_request)
        value = {'choices': [{'message': {'role': 'assistant', 'content': response.text}, 'finish_reason': 'stop'}]}
        return httpx.Response(200, stream=Bytes(json.dumps(value).encode()), headers={'content-type': 'application/json'})
    original = model_smoke.configured_adapter
    def configured(provider, *args, **kwargs):
        if provider == 'glm':
            return GLMAdapter('synthetic-glm', 'https://local.example.invalid/v1/chat/completions',
                              http=JsonHTTP(httpx.MockTransport(handler)))
        return original(provider, *args, **kwargs)
    monkeypatch.setattr(model_smoke, 'configured_adapter', configured)
    report, _ = collected(tmp_path, ['glm', 'mock-review-a'], ['B09', 'B11'])
    assert report['status'] == 'COMPLETE' and report['cleanup']['completed']
    assert report['analysis']['provider_metrics']['glm']['classified'] == 2
