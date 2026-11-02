from recovery import restore_protection
from test_migration import Clock, GitHub, RULE


def test_common_restoration_confirms_original_configuration_and_summary():
    remote = GitHub()
    summary = restore_protection(remote, RULE, clock=Clock(), started=0)
    assert summary == {'attempts': 1, 'restored': True, 'incident': False,
                       'time_reliable': True, 'elapsed_seconds': 0, 'last_error': None, 'errors': []}
    assert remote.events == ['active']
    assert remote.rule == RULE


def test_common_restoration_retries_unknown_write_and_escalates_after_target(capsys):
    clock = Clock()
    class Uncertain(GitHub):
        attempts = 0
        def set_ruleset(self, payload):
            self.attempts += 1
            if self.attempts <= 3:
                clock.seconds += 50
                raise TimeoutError('sensitive text must not be emitted')
            super().set_ruleset(payload)
    remote = Uncertain()
    summary = restore_protection(remote, RULE, clock=clock, started=0)
    assert summary['restored'] is True and summary['attempts'] == 4
    assert summary['incident'] is True
    assert summary['last_error'] == 'RESTORE_TimeoutError'
    output = capsys.readouterr().err
    assert 'RECOVERY_INCIDENT' in output and 'sensitive text' not in output
    assert 'merge' not in remote.events

import pytest


@pytest.mark.parametrize('phase', ['write', 'sleep'])
def test_common_restoration_returns_unconfirmed_summary_on_interruption(phase):
    class Interrupted(GitHub):
        def set_ruleset(self, payload):
            if phase == 'write':
                raise KeyboardInterrupt()
            raise TimeoutError()
    clock = Clock()
    def interrupt(seconds):
        raise KeyboardInterrupt()
    clock.sleep = interrupt
    summary = restore_protection(Interrupted(), RULE, clock=clock, started=0)
    assert summary['restored'] is False and summary['attempts'] == 1
    assert summary['last_error'] == 'RECOVERY_INTERRUPTED_USE_BACKUP'

from datetime import datetime, timezone


@pytest.mark.parametrize('offset,reliable,incident', [(-125, True, True), (-30, True, False), (30, False, True)])
def test_restart_elapsed_time_is_not_reset(offset, reliable, incident, capsys):
    clock = Clock()
    evidence = {'possibly_disabled': True,
                'intent_time': datetime.fromtimestamp(clock.time()+offset, timezone.utc).isoformat()}
    summary = restore_protection(GitHub(), RULE, clock=clock, evidence=evidence)
    assert summary['restored'] is True
    assert summary['time_reliable'] is reliable
    assert summary['incident'] is incident
    assert ('RECOVERY_INCIDENT' in capsys.readouterr().err) is incident


@pytest.mark.parametrize('matches', [True, False])
def test_proven_no_disable_performs_read_only_and_reports_truthful_summary(matches):
    remote = GitHub()
    if not matches:
        remote.rule = {**RULE, 'enforcement': 'disabled'}
    summary = restore_protection(remote, RULE, clock=Clock(), evidence={'possibly_disabled': False})
    assert summary['attempts'] == 0
    assert summary['restored'] is matches
    assert summary['incident'] is False
    assert remote.writes == []


def test_event_output_failure_cannot_block_restoration():
    def broken_output(message):
        raise OSError('logging storage unavailable')
    remote = GitHub()
    summary = restore_protection(remote, RULE, clock=Clock(), emit=broken_output)
    assert summary['incident'] is True and summary['restored'] is True
    assert remote.events == ['active']


def test_logging_and_stderr_failure_cannot_block_protected_remote_restore(tmp_path):
    from contextlib import redirect_stderr
    from runtime import Journal, ProtectedRemote
    class BrokenStream:
        def write(self, text):
            raise OSError('stderr unavailable')
        def flush(self):
            raise OSError('stderr unavailable')
    journal = Journal(tmp_path/'run')
    remote = GitHub()
    protected = ProtectedRemote(remote, journal)
    protected.observe()
    journal.path.unlink()
    journal.path.mkdir()
    with redirect_stderr(BrokenStream()):
        protected.set_ruleset(RULE)
        assert protected.read_ruleset(recovery=True) == RULE
    assert remote.events == ['observe', 'active']


@pytest.mark.parametrize('method', ['GET', 'PUT'])
def test_transport_evidence_failure_cannot_hide_ruleset_response(tmp_path, method):
    from contextlib import redirect_stderr
    import json
    from github_adapter import GhTransport
    from runtime import Journal
    class BrokenStream:
        def write(self, text):
            raise OSError('stderr unavailable')
        def flush(self):
            raise OSError('stderr unavailable')
    journal = Journal(tmp_path/'run')
    journal.path.unlink()
    journal.path.mkdir()
    transport = GhTransport(write_enabled=True, evidence=journal,
                            runner=lambda *args, **kwargs: json.dumps(RULE).encode())
    with redirect_stderr(BrokenStream()):
        assert transport.request(method, 'rulesets/24512048', RULE if method == 'PUT' else None) == RULE


@pytest.mark.parametrize('unavailable', ['time', 'monotonic'])
def test_unavailable_clock_marks_incident_without_blocking_restore(unavailable):
    clock = Clock()
    def failed_clock():
        raise OSError('clock unavailable')
    setattr(clock, unavailable, failed_clock)
    evidence = {'possibly_disabled': True, 'intent_time': '2026-11-01T00:00:00+00:00'}
    remote = GitHub()
    summary = restore_protection(remote, RULE, clock=clock, evidence=evidence)
    assert summary['restored'] is True and summary['incident'] is True
    assert summary['time_reliable'] is False
    assert remote.events == ['active']
