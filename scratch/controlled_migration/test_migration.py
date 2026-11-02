from migration import run


class Remote:
    def __init__(self):
        self.writes = []


def test_default_is_dry_run_with_zero_remote_writes():
    remote = Remote()
    assert run({}, remote)['status'] == 'DRY_RUN'
    assert remote.writes == []


def test_execute_without_explicit_authorization_has_zero_writes():
    remote = Remote()
    assert run({}, remote, execute=True)['status'] == 'NOT_AUTHORIZED'
    assert remote.writes == []

from copy import deepcopy
import pytest

PLAN = {
    'repository': 'chinchiang/MultiAgentEpsilon', 'pr': 64, 'ruleset_id': 24512048,
    'expected_head_sha': 'f7e424b47fed9e4a27d10b2f73b3a6e3278508b7',
    'expected_base_sha': '469ce1850177703bd022a7d65a841dac7dc01994',
}
RULE = {'name': 'protected main', 'target': 'branch', 'enforcement': 'active',
        'bypass_actors': [], 'conditions': {'ref_name': {'include': ['refs/heads/main'], 'exclude': []}},
        'rules': [{'type': 'deletion'}]}

PLAN['expected_ruleset'] = deepcopy(RULE)


class Clock:
    def __init__(self):
        self.seconds = 0
    def monotonic(self):
        return self.seconds
    def time(self):
        return 1800000000
    def sleep(self, seconds):
        self.seconds += seconds


def consent():
    return {**PLAN, 'authorized': True, 'maintenance_freeze_confirmed': True,
            'backup_recovery_confirmed': True, 'expires_at': 1800000300,
            'approved_by': 'offline-test-owner', 'approval_reference': 'offline-only'}


class GitHub(Remote):
    def __init__(self):
        super().__init__()
        self.rule = deepcopy(RULE)
        self.events = []
        self.snapshot = {**PLAN, 'open': True, 'draft': False,
                         'review_valid': True, 'guard_valid': True,
                         'other_protection_absent': True,
                         'only_expected_lock_diff': True, 'ruleset': deepcopy(RULE)}
    def observe(self, **kwargs):
        self.events.append('observe')
        return deepcopy(self.snapshot)
    def set_ruleset(self, payload):
        self.writes.append(deepcopy(payload))
        self.events.append(payload['enforcement'])
        self.rule = deepcopy(payload)
    def read_ruleset(self, **kwargs):
        return deepcopy(self.rule)
    def merge(self, head):
        self.writes.append({'merge': head})
        self.events.append('merge')
    def inspect_outcome(self):
        self.events.append('inspect')
        return {'merged': True, 'merge_sha': 'a' * 40, 'parents': [PLAN['expected_base_sha'], PLAN['expected_head_sha']],
                'only_expected_lock_diff': True, 'formal_push_ci': 'pending',
                'full_mutation': 'pending', 'signature': 'pending'}


def test_authorized_coordinator_restores_before_reading_merge_outcome():
    remote = GitHub()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['status'] == 'PENDING_ACCEPTANCE'
    assert result['restored'] is True
    assert result['accepted'] is False
    assert remote.events == ['observe', 'disabled', 'observe', 'merge', 'active', 'inspect']
    assert remote.rule == RULE


@pytest.mark.parametrize('field,value', [
    ('expected_head_sha', 'b' * 40), ('expected_base_sha', 'c' * 40),
    ('repository', 'other/repo'), ('pr', 65), ('ruleset_id', 1),
    ('open', False), ('draft', True), ('review_valid', False),
    ('guard_valid', False), ('other_protection_absent', False),
    ('only_expected_lock_diff', False),
])
def test_drift_or_missing_preconditions_prevent_all_writes(field, value):
    remote = GitHub()
    remote.snapshot[field] = value
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['status'] == 'PREFLIGHT_BLOCKED'
    assert remote.writes == []


@pytest.mark.parametrize('field,value', [
    ('authorized', False), ('maintenance_freeze_confirmed', False),
    ('backup_recovery_confirmed', False), ('expires_at', 1800000000),
    ('expires_at', 'tomorrow'), ('approval_reference', ''), ('approved_by', ''),
    ('expected_head_sha', 'b' * 40), ('expected_base_sha', 'c' * 40),
])
def test_invalid_authorization_cannot_write(field, value):
    remote = GitHub()
    auth = consent()
    auth[field] = value
    assert run(PLAN, remote, execute=True, authorization=auth, clock=Clock())['status'] == 'NOT_AUTHORIZED'
    assert remote.writes == []


@pytest.mark.parametrize('failure', ['disable_timeout', 'merge_timeout', 'drift', 'cutoff', 'readback_drift'])
def test_uncertain_or_changed_state_restores_before_inspection(failure):
    clock = Clock()
    class Faulty(GitHub):
        def set_ruleset(self, payload):
            super().set_ruleset(payload)
            if payload['enforcement'] == 'disabled':
                if failure == 'disable_timeout':
                    raise TimeoutError('response lost after side effect')
                if failure == 'cutoff':
                    clock.seconds = 60
        def observe(self, **kwargs):
            snapshot = super().observe(**kwargs)
            if self.writes and failure == 'drift':
                snapshot['expected_base_sha'] = 'd' * 40
            return snapshot
        def read_ruleset(self, **kwargs):
            value = super().read_ruleset(**kwargs)
            if value['enforcement'] == 'disabled' and failure == 'readback_drift':
                value['rules'] = []
            return value
        def merge(self, head):
            super().merge(head)
            if failure == 'merge_timeout':
                raise TimeoutError('merge result unknown')
    remote = Faulty()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=clock)
    assert result['restored'] is True
    assert result['accepted'] is False
    assert remote.events.index('active') < remote.events.index('inspect')
    assert remote.events.count('merge') == (1 if failure == 'merge_timeout' else 0)
    assert result['errors']


def test_restore_retries_past_target_and_never_merges_again():
    clock = Clock()
    class BrokenRecovery(GitHub):
        attempts = 0
        def set_ruleset(self, payload):
            if payload['enforcement'] == 'active':
                self.attempts += 1
                if self.attempts <= 3:
                    clock.seconds += 50
                    raise TimeoutError('restore response lost')
            super().set_ruleset(payload)
    remote = BrokenRecovery()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=clock)
    assert result['restored'] is True
    assert result['window_exceeded'] is True
    assert remote.attempts == 4
    assert remote.events.count('merge') == 1


def test_interrupted_recovery_reports_incident_without_inspecting_outcome():
    class InterruptedRecovery(GitHub):
        def set_ruleset(self, payload):
            if payload['enforcement'] == 'active':
                raise KeyboardInterrupt()
            super().set_ruleset(payload)
    remote = InterruptedRecovery()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['status'] == 'RECOVERY_REQUIRED'
    assert result['restored'] is False
    assert result['accepted'] is False
    assert 'inspect' not in remote.events
    assert result['restore_payload'] == RULE


@pytest.mark.parametrize('problem', ['parents', 'diff', 'ci', 'mutation', 'signature', 'merged', 'sha'])
def test_acceptance_requires_every_formal_evidence(problem):
    class Outcome(GitHub):
        def inspect_outcome(self):
            value = super().inspect_outcome()
            value.update(formal_push_ci='success', full_mutation='success', signature='success')
            key = {'parents': 'parents', 'diff': 'only_expected_lock_diff', 'ci': 'formal_push_ci',
                   'mutation': 'full_mutation', 'signature': 'signature', 'merged': 'merged', 'sha': 'merge_sha'}[problem]
            value[key] = {'parents': ['wrong'], 'diff': False, 'ci': 'failure', 'mutation': 'pending',
                          'signature': 'pending', 'merged': False, 'sha': 'invalid'}[problem]
            return value
    result = run(PLAN, Outcome(), execute=True, authorization=consent(), clock=Clock())
    assert result['accepted'] is False
    assert result['status'] in ('PENDING_ACCEPTANCE', 'ACCEPTANCE_FAILED')


def test_all_verified_evidence_allows_acceptance():
    class Verified(GitHub):
        def inspect_outcome(self):
            value = super().inspect_outcome()
            value.update(formal_push_ci='success', full_mutation='success', signature='success')
            return value
    result = run(PLAN, Verified(), execute=True, authorization=consent(), clock=Clock())
    assert result['accepted'] is True
    assert result['restored'] is True
    assert result['status'] == 'ACCEPTED'


def test_live_state_adapter_can_report_disabled_ruleset_during_window():
    class CurrentState(GitHub):
        def observe(self, **kwargs):
            value = super().observe(**kwargs)
            value['ruleset'] = deepcopy(self.rule)
            return value
    result = run(PLAN, CurrentState(), execute=True, authorization=consent(), clock=Clock())
    assert result['status'] == 'PENDING_ACCEPTANCE'
    assert result['errors'] == []

import json
import subprocess
import sys
from pathlib import Path


def test_cli_defaults_to_offline_dry_run():
    process = subprocess.run([sys.executable, str(Path(__file__).with_name('migration.py'))],
                             capture_output=True, text=True, timeout=5)
    assert process.returncode == 0
    assert json.loads(process.stdout)['status'] == 'DRY_RUN'


def test_cli_refuses_live_execution_instead_of_inventing_authorization():
    process = subprocess.run([sys.executable, str(Path(__file__).with_name('migration.py')), '--execute'],
                             capture_output=True, text=True, timeout=5)
    assert process.returncode != 0
    assert 'NOT_AUTHORIZED' in process.stdout


@pytest.mark.parametrize('phase', ['preflight', 'outcome'])
def test_unavailable_read_evidence_is_reported_without_new_remote_mutations(phase):
    class MissingEvidence(GitHub):
        def observe(self, **kwargs):
            if phase == 'preflight':
                raise TimeoutError('cannot establish preconditions')
            return super().observe(**kwargs)
        def inspect_outcome(self):
            raise TimeoutError('CI evidence unavailable')
    remote = MissingEvidence()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['status'] == ('PREFLIGHT_BLOCKED' if phase == 'preflight' else 'PENDING_ACCEPTANCE')
    assert result['accepted'] is False
    assert result['errors']
    if phase == 'preflight':
        assert remote.writes == []
    else:
        assert result['restored'] is True
        assert remote.events.count('merge') == 1


def test_failed_ci_is_failed_acceptance_with_protection_kept_active():
    class FailedCI(GitHub):
        def inspect_outcome(self):
            value = super().inspect_outcome()
            value['formal_push_ci'] = 'failure'
            return value
    remote = FailedCI()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['status'] == 'ACCEPTANCE_FAILED'
    assert remote.rule['enforcement'] == 'active'
    assert remote.events.count('disabled') == 1


def test_restore_readback_mismatch_is_repaired_before_inspection():
    class StaleReadback(GitHub):
        bad_read = True
        def read_ruleset(self, **kwargs):
            value = super().read_ruleset(**kwargs)
            if value['enforcement'] == 'active' and self.bad_read:
                self.bad_read = False
                value['rules'] = []
            return value
    remote = StaleReadback()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['restored'] is True
    assert remote.events.count('active') == 2
    assert remote.events[-1] == 'inspect'


def test_rules_changed_since_review_stop_before_disable():
    plan = {**PLAN, 'expected_ruleset': deepcopy(RULE)}
    remote = GitHub()
    remote.snapshot['ruleset']['rules'].append({'type': 'non_fast_forward'})
    result = run(plan, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['status'] == 'PREFLIGHT_BLOCKED'
    assert remote.writes == []


def test_authorization_expiring_during_preflight_prevents_disable():
    clock = Clock()
    class SlowPreflight(GitHub):
        def observe(self, **kwargs):
            snapshot = super().observe(**kwargs)
            clock.time = lambda: 1800000300
            return snapshot
    remote = SlowPreflight()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=clock)
    assert result['status'] == 'NOT_AUTHORIZED'
    assert remote.writes == []


def test_recovery_failures_emit_operator_alerts(capsys):
    class OnceUnavailable(GitHub):
        failed = False
        def set_ruleset(self, payload):
            if payload['enforcement'] == 'active' and not self.failed:
                self.failed = True
                raise TimeoutError()
            super().set_ruleset(payload)
    result = run(PLAN, OnceUnavailable(), execute=True, authorization=consent(), clock=Clock())
    assert result['restored'] is True
    assert 'RECOVERY_RETRY' in capsys.readouterr().err


def test_normal_coordinator_exposes_common_recovery_summary_and_preserves_counts():
    remote = GitHub()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=Clock())
    assert result['recovery']['attempts'] == 1
    assert result['recovery']['restored'] is True
    assert result['remote_writes'] == 3
    assert result['status'] == 'PENDING_ACCEPTANCE'


def test_clock_failure_after_disable_does_not_discard_confirmed_recovery():
    clock = Clock()
    samples = 0
    def monotonic():
        nonlocal samples
        samples += 1
        if samples > 1:
            raise OSError('clock unavailable')
        return 0
    clock.monotonic = monotonic
    remote = GitHub()
    result = run(PLAN, remote, execute=True, authorization=consent(), clock=clock)
    assert result['restored'] is True
    assert result['recovery']['incident'] is True
    assert result['recovery']['time_reliable'] is False
    assert remote.events.index('active') < remote.events.index('inspect')
    assert 'merge' not in remote.events
