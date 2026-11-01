"""限定 PR #64 與指定規則集的 GitHub 介接器。"""
from copy import deepcopy
from migration import FIELDS, SCOPE


def need(condition, code):
    if not condition:
        raise ValueError(code)


class GitHubAdapter:
    def __init__(self, transport, reference):
        self.transport = transport
        self.reference = {k: deepcopy(reference[k]) for k in FIELDS}
        self.merge_sent = False

    def set_ruleset(self, payload):
        normalized = {**deepcopy(payload), 'enforcement': 'active'}
        need(normalized == self.reference and payload.get('enforcement') in ('active', 'disabled'), 'RULE_SCOPE')
        return self.transport.request('PUT', 'rulesets/24512048', payload)

    def merge(self, head):
        need(head == SCOPE['expected_head_sha'] and not self.merge_sent, 'MERGE_SCOPE')
        self.merge_sent = True
        return self.transport.request('PUT', 'pulls/64/merge', {'sha': head, 'merge_method': 'merge'})

    def read_ruleset(self, *, recovery=False, deadline=None, clock=None):
        raw = self.transport.request('GET', 'rulesets/24512048', recovery=recovery, deadline=deadline, clock=clock)
        return {k: raw[k] for k in FIELDS}


    def observe(self, *, deadline=None, clock=None):
        from security_harness.trusted_publisher import validate_review, validate_run_base, unpack_evidence
        get = lambda path, **kwargs: self.transport.request('GET', path, deadline=deadline, clock=clock, **kwargs)
        items = lambda path, key=None: self.transport.items(path, key=key, deadline=deadline, clock=clock)
        need(get('user')['login'] == 'chinchiang', 'IDENTITY')
        need(get('collaborators/chinchiang/permission')['permission'] == 'admin', 'ADMIN_REQUIRED')
        pr = get('pulls/64')
        base, head = SCOPE['expected_base_sha'], SCOPE['expected_head_sha']
        need(get('branches/main')['commit']['sha'] == base, 'MAIN_DRIFT')
        need(pr['head']['sha'] == head and pr['base']['sha'] == base
             and pr['base']['ref'] == 'main' and pr['base']['repo']['full_name'] == SCOPE['repository']
             and pr['head']['repo']['full_name'] == SCOPE['repository']
             and pr['state'] == 'open' and pr['draft'] is False, 'PR_DRIFT')
        rules = items('rulesets?includes_parents=true')
        need(len(rules) == 1 and rules[0]['id'] == 24512048, 'OTHER_RULESETS')
        need(get('branches/main/protection', allow_404=True) is None, 'LEGACY_PROTECTION')
        rule = self.read_ruleset(deadline=deadline, clock=clock)
        normalized = {**deepcopy(rule), 'enforcement': 'active'}
        need(normalized == self.reference, 'RULE_DRIFT')
        comparison = get(f'compare/{base}...{head}')
        need(self.valid_diff(comparison), 'LOCK_DIFF')
        reviews = items('pulls/64/reviews')
        permissions = {r['user']['login']: get('collaborators/'+r['user']['login']+'/permission')['permission']
                       for r in reviews}
        commits = items('pulls/64/commits')
        need(len(commits) == 1 and commits[0]['sha'] == head, 'COMMIT_SCOPE')
        workflow = get('actions/workflows/security.yml')
        runs = items(f'actions/workflows/security.yml/runs?event=pull_request_target&head_sha={head}', key='workflow_runs')
        need(bool(runs), 'GUARD_RUN_MISSING')
        run = max(runs, key=lambda r: r['id'])
        need(run['event'] == 'pull_request_target' and run['status'] == 'completed'
             and run['workflow_id'] == workflow['id'] and run['path'] == '.github/workflows/security.yml'
             and run['repository']['full_name'] == SCOPE['repository'], 'GUARD_SOURCE')
        related = items('pulls?state=all&head=chinchiang:' + pr['head']['ref'])
        histories = {p['number']: items(f"issues/{p['number']}/timeline") for p in related}
        validate_run_base(run, pr, related, 'main', histories)
        excluded = {'chinchiang', run.get('actor', {}).get('login'), run.get('triggering_actor', {}).get('login')}
        for commit in commits:
            excluded.update((commit.get('author', {}).get('login'), commit.get('committer', {}).get('login')))
        ids = validate_review(pr, reviews, permissions, {'reviewers': ['CatGrocery', 'd98922036ntu']}, excluded)
        jobs = items(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", key='jobs')
        guard_jobs = [j for j in jobs if j['name'] == 'trusted-security-evaluation']
        need(len(guard_jobs) == 1 and guard_jobs[0]['run_id'] == run['id']
             and guard_jobs[0]['run_attempt'] == run['run_attempt']
             and any(step['name'] == 'Check protected changes and exact-head independent approval'
                     and step.get('conclusion') == 'success' for step in guard_jobs[0]['steps']), 'GUARD_STEP')
        artifacts = items(f"actions/runs/{run['id']}/artifacts", key='artifacts')
        matches = [a for a in artifacts if a['name'] == f"trusted-security-{run['id']}-{run['run_attempt']}"
                   and a.get('expired') is False]
        need(len(matches) == 1, 'GUARD_ARTIFACT')
        raw = get(f"actions/artifacts/{matches[0]['id']}/zip", binary=True)
        files = unpack_evidence(raw)
        guard = strict_json(files['audit/trusted-guard.json'])
        provenance = strict_json(files['audit/ci-provenance.json'])
        need(guard.get('schema_version') == 2 and guard.get('decision') == 'ALLOW'
             and guard.get('base_sha') == base and guard.get('candidate_sha') == head
             and guard.get('baseline_approval', {}).get('review_id') in ids
             and guard['baseline_approval'].get('commit_id') == head, 'GUARD_BINDING')
        expected = {'schema_version': 1, 'repository': SCOPE['repository'], 'repository_id': pr['base']['repo']['id'],
                    'run_id': run['id'], 'run_attempt': run['run_attempt'], 'event': 'pull_request_target',
                    'workflow_sha': base, 'base_sha': base, 'candidate_sha': head, 'pr_number': 64,
                    'workflow_ref': SCOPE['repository']+'/.github/workflows/security.yml@refs/heads/main'}
        need(all(provenance.get(k) == v for k, v in expected.items()), 'GUARD_PROVENANCE')
        return {**SCOPE, 'open': True, 'draft': False, 'review_valid': True, 'guard_valid': True,
                'other_protection_absent': True, 'only_expected_lock_diff': True, 'ruleset': rule,
                'guard_run_id': run['id'], 'guard_attempt': run['run_attempt'], 'review_ids': ids}

    def inspect_outcome(self):
        from security_harness.trusted_publisher import unpack_evidence
        get = lambda path, **kwargs: self.transport.request('GET', path, **kwargs)
        pr = get('pulls/64')
        outcome = {'merged': pr.get('merged') is True, 'merge_sha': pr.get('merge_commit_sha'),
                   'parents': [], 'only_expected_lock_diff': False, 'formal_push_ci': 'pending',
                   'full_mutation': 'pending', 'signature': 'pending'}
        if not outcome['merged']:
            return outcome
        sha = outcome['merge_sha']
        need(bool(re.fullmatch('[0-9a-f]{40}', sha or '')), 'MERGE_SHA')
        commit = get('commits/' + sha)
        outcome['parents'] = [parent['sha'] for parent in commit['parents']]
        outcome['only_expected_lock_diff'] = self.valid_diff(get(f"compare/{SCOPE['expected_base_sha']}...{sha}"))
        if outcome['parents'] != [SCOPE['expected_base_sha'], SCOPE['expected_head_sha']] or not outcome['only_expected_lock_diff']:
            return outcome
        workflow = get('actions/workflows/security.yml')
        runs = self.transport.items(f'actions/workflows/security.yml/runs?event=push&head_sha={sha}', key='workflow_runs')
        if not runs:
            return outcome
        run = max(runs, key=lambda r: r['id'])
        outcome.update(run_id=run['id'], run_attempt=run['run_attempt'])
        need(run['event'] == 'push' and run['head_sha'] == sha and run['head_branch'] == 'main'
             and run['path'] == '.github/workflows/security.yml' and run['workflow_id'] == workflow['id']
             and run['repository']['full_name'] == SCOPE['repository'], 'PUSH_SOURCE')
        if run['status'] != 'completed':
            return outcome
        if run['conclusion'] != 'success':
            outcome['formal_push_ci'] = 'failure'
            return outcome
        jobs = self.transport.items(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", key='jobs')
        required = {'trusted-security-evaluation', 'trusted-mutation-tests',
                    'Attest evaluator-owned evidence', 'trusted-security-pilot'}
        selected = [j for j in jobs if j.get('name') in required]
        need(len(selected) == 4 and {j['name'] for j in selected} == required
             and all(j.get('conclusion') == 'success' and j.get('run_id') == run['id']
                     and j.get('run_attempt') == run['run_attempt'] for j in selected), 'PUSH_JOBS')
        artifacts = self.transport.items(f"actions/runs/{run['id']}/artifacts", key='artifacts')
        archives = {}
        for kind in ('security', 'mutations'):
            matching = [a for a in artifacts if a.get('name') == f"trusted-{kind}-{run['id']}-{run['run_attempt']}"
                        and a.get('expired') is False]
            need(len(matching) == 1, 'PUSH_ARTIFACT')
            archives[kind] = get(f"actions/artifacts/{matching[0]['id']}/zip", binary=True)
        files = unpack_evidence(archives['security'])
        provenance = strict_json(files['audit/ci-provenance.json'])
        expected = {'event': 'push', 'workflow_sha': sha, 'base_sha': sha, 'candidate_sha': sha,
                    'run_id': run['id'], 'run_attempt': run['run_attempt'], 'repository': SCOPE['repository'],
                    'workflow_ref': SCOPE['repository']+'/.github/workflows/security.yml@refs/heads/main'}
        need(all(provenance.get(k) == v for k, v in expected.items()), 'PUSH_PROVENANCE')
        outcome['formal_push_ci'] = 'success'
        mutations = [strict_json(data) for name, data in unpack_evidence(archives['mutations']).items()
                     if name.endswith('/report.json')]
        need(len(mutations) == 1, 'MUTATION_REPORT')
        report = mutations[0]
        expected_targets = {'security_harness/results.py', 'security_harness/github_http.py',
                            'security_harness/preflight.py', 'security_harness/authorization.py',
                            'security_harness/isolation.py', 'security_harness/scope.py',
                            'security_harness/llm/benchmark.py'}
        mutants, baselines = report.get('mutants', []), report.get('baselines', [])
        campaign_valid = (report.get('status') == 'COMPLETE' and report.get('mutation_score') == 1.0
             and report.get('counts') == {'KILLED': 206, 'SURVIVED': 0, 'TIMEOUT': 0, 'ERROR': 0}
             and report.get('cleanup_completed') is True and set(report.get('scope', {})) == expected_targets
             and len(mutants) == 206 and all(m.get('status') == 'KILLED' for m in mutants)
             and len({m.get('id') for m in mutants}) == 206
             and len(baselines) == 7 and {b.get('target') for b in baselines} == expected_targets
             and all(b.get('passed') is True and b.get('normalized_passed') is True for b in baselines))
        outcome['full_mutation'] = 'success' if campaign_valid else 'failure'
        try:
            verified = self.transport.verify_attestation(archives['security'], run, sha)
            outcome['signature'] = 'success' if verified is True else 'failure'
        except ValueError:
            outcome['signature'] = 'failure'
        return outcome

    @staticmethod
    def valid_diff(comparison):
        files = comparison.get('files', [])
        return (len(files) == 1 and files[0].get('filename') == 'requirements.lock'
                and files[0].get('status') == 'modified'
                and files[0].get('sha') == 'e428ccd6d661fdd0188dcdf3530e5a7846c3acd4')


import json
import os
from pathlib import Path
import re
import shutil
import sys
from urllib.parse import urlsplit, unquote
from uuid import uuid4
import time
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from security_harness.processes import bounded_output
from security_harness.github_http import strict_json


class GhTransport:
    """沿用 gh credential store；每次 HTTP 請求 12 秒、JSON 2 MiB。"""
    def __init__(self, *, write_enabled=False, runner=bounded_output, evidence=None):
        self.session = uuid4().hex[:12]
        self.evidence = evidence
        self.write_enabled = write_enabled
        self.runner = runner
        self.gh = shutil.which('gh')
        need(self.gh is not None, 'GH_MISSING')
        self.env = {k: v for k, v in os.environ.items() if k in {
            'PATH', 'HOME', 'XDG_CONFIG_HOME', 'GH_CONFIG_DIR', 'HTTPS_PROXY', 'HTTP_PROXY',
            'ALL_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'SSL_CERT_DIR'}}
        self.env.update(GH_PROMPT_DISABLED='1', GH_NO_UPDATE_NOTIFIER='1', GH_HOST='github.com')
        self.calls = 0

    def request(self, method, path, payload=None, *, binary=False, allow_404=False, recovery=False, deadline=None, clock=None):
        parts = urlsplit(path)
        need(not parts.scheme and not parts.netloc and not path.startswith('/') and not parts.fragment
             and '..' not in unquote(parts.path).split('/') and '\\' not in path, 'DESTINATION')
        need(method in ('GET', 'PUT'), 'METHOD')
        if method == 'PUT':
            need(self.write_enabled, 'WRITE_NOT_AUTHORIZED')
            need(path in ('rulesets/24512048', 'pulls/64/merge'), 'WRITE_SCOPE')
        need(method == 'PUT' or payload is None, 'READ_PAYLOAD')
        need(not recovery or (method == 'GET' and path == 'rulesets/24512048'), 'RECOVERY_READ_SCOPE')
        self.calls += 1
        # 必要恢復讀回與恢復寫入都不能因一般查核預算耗盡而遭拒。
        need(method == 'PUT' or recovery or self.calls <= 1500, 'READ_BUDGET')
        endpoint = 'user' if path == 'user' else 'repos/' + SCOPE['repository'] + '/' + path
        command = [self.gh, 'api', '--hostname', 'github.com', '--method', method,
                   '--header', 'Accept: application/vnd.github+json',
                   '--header', 'X-GitHub-Api-Version: 2022-11-28']
        if allow_404:
            # 固定 shell 程式只保留 gh HTTP 回應；參數經 argv 傳入，沒有插值。
            command += ['--include']
        command += [endpoint]
        raw = b''
        if payload is not None:
            command += ['--input', '-']
            raw = json.dumps(payload, separators=(',', ':')).encode()
        if allow_404:
            command = ['/bin/sh', '-c', '"$@"; exit 0', 'migration-http', *command]
        clock = clock or time
        remaining = 12 if deadline is None else min(12, deadline-clock.monotonic())
        if remaining <= 0:
            raise TimeoutError('MERGE_WINDOW_EXPIRED')
        response = self.runner(command, raw, timeout=remaining, limit=16*1024**2 if binary else 2*1024**2, env=self.env)
        if deadline is not None and clock.monotonic() >= deadline:
            raise TimeoutError('MERGE_WINDOW_EXPIRED')
        if allow_404:
            head, separator, body = response.replace(b'\r\n', b'\n').partition(b'\n\n')
            status = re.match(rb'HTTP/\S+ (\d{3})', head)
            need(separator and status, 'HTTP_RESPONSE')
            code = int(status[1])
            if code == 404:
                need(strict_json(body).get('message') == 'Branch not protected', 'AMBIGUOUS_404')
                return None
            need(code == 200, 'HTTP_STATUS')
            response = body
        if self.evidence is not None:
            name = f'github-{self.session}-{self.calls:05d}.'+('zip' if binary else 'json')
            try:
                self.evidence.save_bytes(name, response)
                self.evidence.record('github_response', method=method, path=path, file=name)
            except OSError:
                if path != 'rulesets/24512048':
                    raise
                print('RECOVERY_HTTP_JOURNAL_UNAVAILABLE', file=sys.stderr, flush=True)
        return response if binary else strict_json(response)

    def items(self, path, key=None, *, deadline=None, clock=None):
        result, totals = [], []
        for page in range(1, 102):
            separator = '&' if '?' in path else '?'
            value = self.request('GET', path + separator + f'per_page=100&page={page}', deadline=deadline, clock=clock)
            if key:
                totals.append(value['total_count'])
                value = value[key]
            need(isinstance(value, list), 'PAGINATION_TYPE')
            result.extend(value)
            need(len(result) <= 10000, 'PAGINATION_LIMIT')
            if len(value) < 100:
                need(all(n == len(result) for n in totals), 'PAGINATION_TOTAL')
                return result
        raise ValueError('PAGINATION_LIMIT')

    def verify_attestation(self, raw, run, sha):
        import hashlib
        import tempfile
        digest = hashlib.sha256(raw).hexdigest()
        response = self.request('GET', 'attestations/sha256:' + digest)
        attestations = response.get('attestations')
        need(isinstance(attestations, list) and 0 < len(attestations) < 30, 'ATTESTATION_LIST')
        bundles = b'\n'.join(json.dumps(a['bundle']).encode() for a in attestations)
        need(len(bundles) <= 2*1024**2, 'ATTESTATION_SIZE')
        with tempfile.TemporaryDirectory(prefix='epsilon-verify-') as directory:
            artifact, bundle = Path(directory)/'artifact.zip', Path(directory)/'bundle.jsonl'
            artifact.write_bytes(raw)
            bundle.write_bytes(bundles)
            env = {**self.env, 'GH_CONFIG_DIR': directory+'/config', 'XDG_CACHE_HOME': directory+'/cache'}
            command = [self.gh, 'attestation', 'verify', str(artifact), '--bundle', str(bundle),
                       '--hostname', 'github.com', '--repo', SCOPE['repository'],
                       '--signer-workflow', SCOPE['repository']+'/.github/workflows/security.yml',
                       '--cert-identity', 'https://github.com/'+SCOPE['repository']+'/.github/workflows/security.yml@refs/heads/main',
                       '--deny-self-hosted-runners', '--predicate-type', 'https://slsa.dev/provenance/v1', '--format', 'json']
            proofs = strict_json(self.runner(command, b'', timeout=60, limit=2*1024**2, env=env))
        if self.evidence is not None:
            self.evidence.save('verified-attestation.json', {'run_id': run['id'], 'run_attempt': run['run_attempt'],
                                                          'artifact_sha256': digest, 'proofs': proofs})
        invocation = f"https://github.com/{SCOPE['repository']}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
        source = 'git+https://github.com/'+SCOPE['repository']+'@refs/heads/main'
        need(isinstance(proofs, list), 'ATTESTATION_RESPONSE')
        for proof in proofs:
            statement = proof.get('verificationResult', {}).get('statement', {})
            predicate = statement.get('predicate', {})
            if (statement.get('predicateType') == 'https://slsa.dev/provenance/v1'
                and predicate.get('runDetails', {}).get('metadata', {}).get('invocationId') == invocation
                and any(s.get('digest', {}).get('sha256') == digest for s in statement.get('subject', []))
                and any(d.get('uri') == source and d.get('digest', {}).get('gitCommit') == sha
                        for d in predicate.get('buildDefinition', {}).get('resolvedDependencies', []))):
                return True
        raise ValueError('ATTESTATION_BINDING')
