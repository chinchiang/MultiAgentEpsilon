"""Known-vulnerability counterexamples and incomplete/tampered coverage block."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from security_harness import dependencies as deps
from security_harness.results import decide, result
from tests.dependency_evidence import clean_evidence

NOW = datetime.now(timezone.utc)
POLICY = {'required_gates': ['G1'], 'max_evidence_age_seconds': 3600,
          'gate_contracts': {'G1': {'kind': 'scan', 'sca_required': True}}}


def judge(evidence, packages, findings=0):
    row = result('G1', 'COMPLETED', 'scan', len(packages), findings, 'subject', 'policy',
                 'offline regression', run_id='run', packages=packages, sca=evidence)
    row['created_at'] = NOW.isoformat()
    return decide([row], POLICY, 'subject', 'policy', NOW, run_id='run')['decision']


def advisory(name='example', **extra):
    return {'id': 'GHSA-example-0001', 'aliases': ['CVE-2026-12345'],
            'affected': [{'package': {'ecosystem': 'PyPI', 'name': name}}], **extra}


def lockfile(tmp_path):
    path = tmp_path / 'requirements.lock'
    path.write_text('example==1.0 --hash=sha256:' + 'a' * 64 + '\n')
    return path


def test_complete_zero_findings_allowed_and_inventory_is_deterministic():
    packages, evidence = clean_evidence(3, NOW)
    assert judge(evidence, packages) == 'ALLOW'
    _, repeated = clean_evidence(3, NOW)
    assert evidence == repeated
    assert evidence['sbom']['specVersion'] == '1.6'
    assert evidence['package_count'] == len(evidence['queries']) == 3


def test_unknown_severity_known_vulnerability_blocks_and_keeps_cve_alias(tmp_path):
    evidence = deps.scan(lockfile(tmp_path), fetch=lambda *args: {'vulns': [advisory()]}, now=NOW)
    packages = [{'name': 'example', 'version': '1.0', 'approved_hashes': ['a' * 64]}]
    assert evidence['findings'][0]['aliases'] == ['CVE-2026-12345']
    assert judge(evidence, packages, 1) == 'BLOCK'
    assert judge(evidence, packages, 0) == 'BLOCK'


@pytest.mark.parametrize('response', [None, [], {'next_page_token': 'more'}, {'vulns': None},
    {'vulns': [advisory('other')]}, {'vulns': [advisory(), advisory()]},
    {'vulns': [advisory(withdrawn='2026-01-01')]}, {'vulns': [{'id': 'x'}]},
    {'vulns': [advisory(aliases='CVE')]}, {'vulns': [advisory(id='bad\nidentifier')]}])
def test_partial_or_wrong_database_response_never_completes(tmp_path, response):
    with pytest.raises(deps.DependencyError):
        deps.scan(lockfile(tmp_path), fetch=lambda *args: response)


def test_unavailable_database_and_changing_lock_do_not_return_clean_scan(tmp_path):
    path = lockfile(tmp_path)
    def unavailable(*args):
        raise TimeoutError('unavailable')
    with pytest.raises(deps.DependencyError) as caught: deps.scan(path, fetch=unavailable)
    assert caught.value.evidence['status'] == 'INCOMPLETE'
    assert caught.value.evidence['queries'][0]['error_type'] == 'TimeoutError'
    def changed(*args):
        path.write_text(path.read_text() + '# change\n')
        return {}
    with pytest.raises(deps.DependencyError, match='lock changed'): deps.scan(path, fetch=changed)


def test_partial_scan_keeps_found_vulnerability_and_failed_query(tmp_path):
    path = lockfile(tmp_path)
    path.write_text(path.read_text() + 'other==1.0 --hash=sha256:' + 'b' * 64 + '\n')
    def mixed(name, version):
        if name == 'other': raise TimeoutError('must not appear in evidence')
        return {'vulns': [advisory(name)]}
    with pytest.raises(deps.DependencyError) as caught:
        deps.scan(path, fetch=mixed)
    evidence = caught.value.evidence
    assert evidence['status'] == 'INCOMPLETE' and evidence['package_count'] == 2
    assert len(evidence['findings']) == 1
    assert [q['status'] for q in evidence['queries']] == ['SUCCESS', 'ERROR']
    assert 'must not appear' not in json.dumps(evidence)


@pytest.mark.parametrize('attack', ['missing-query', 'duplicate-query', 'wrong-version', 'empty-sbom',
    'hash', 'future', 'stale', 'missing-findings', 'hidden-finding', 'source', 'boolean-count',
    'partial', 'wrong-package', 'missing-hashes', 'lock-hash', 'boolean-schema'])
def test_tampered_or_incomplete_evidence_blocks(attack):
    packages, evidence = clean_evidence(2, NOW)
    if attack == 'missing-query': evidence['queries'].pop()
    elif attack == 'duplicate-query': evidence['queries'][1] = deepcopy(evidence['queries'][0])
    elif attack == 'wrong-version': evidence['queries'][0]['version'] = '0.1'
    elif attack == 'empty-sbom': evidence['sbom']['components'] = []
    elif attack == 'hash': evidence['sbom_sha256'] = '0' * 64
    elif attack == 'future': evidence['queried_at'] = (NOW + timedelta(seconds=1)).isoformat()
    elif attack == 'stale': evidence['queried_at'] = (NOW - timedelta(hours=2)).isoformat()
    elif attack == 'missing-findings': del evidence['findings']
    elif attack == 'hidden-finding': evidence['queries'][0]['advisory_ids'] = ['CVE-2026-12345']
    elif attack == 'source': evidence['source'] = 'https://attacker.invalid'
    elif attack == 'boolean-count': evidence['package_count'] = True
    elif attack == 'partial': evidence['status'] = 'INCOMPLETE'
    elif attack == 'wrong-package': packages[0]['name'] = 'wrong'
    elif attack == 'missing-hashes': del packages[0]['approved_hashes']
    elif attack == 'lock-hash': evidence['lock_sha256'] = 'not-a-digest'
    elif attack == 'boolean-schema': evidence['schema_version'] = True
    assert judge(evidence, packages) == 'BLOCK'


@pytest.mark.parametrize('raw', [b'{"vulns":[],"vulns":[]}', b'{"x":NaN}'])
def test_ambiguous_json_refused(raw):
    with pytest.raises(deps.DependencyError): deps.strict_json(raw)


def test_network_request_has_fixed_host_exact_identity_limits_and_no_redirect(monkeypatch):
    seen = {}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            seen['limit'] = limit
            return b'{}'
    class Opener:
        def open(self, request, timeout):
            seen.update(url=request.full_url, body=json.loads(request.data), timeout=timeout)
            return Response()
    def build(handler):
        assert isinstance(handler, deps.NoRedirect)
        return Opener()
    monkeypatch.setattr(deps.urllib.request, 'build_opener', build)
    assert deps.query('example', '1.0') == {}
    assert seen == {'url': deps.ENDPOINT, 'body': {'package': {'name': 'example', 'ecosystem': 'PyPI'},
        'version': '1.0'}, 'timeout': 20, 'limit': deps.MAX_RESPONSE + 1}
