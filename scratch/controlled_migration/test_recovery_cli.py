from datetime import datetime, timezone
import json
import time
import pytest
from command import main
from runtime import Journal, sync_json
from test_migration import RULE
from test_github import repository
from test_runtime import workspace_with_receipt


def prepared_restart(tmp_path, raw):
    plan, auth, receipt = workspace_with_receipt(tmp_path)
    auth['expires_at'] = time.time()-100
    receipt.write_text(json.dumps(auth))
    state = tmp_path/'scratch/controlled-migration-state'
    journal = Journal(state/'prior-run')
    for name, data in [('plan.json', plan), ('authorization.json', auth), ('recovery.json', {'ruleset': RULE})]:
        journal.save(name, data)
    journal.path.write_bytes(raw)
    sync_json(state/'active.json', {'directory': str(journal.directory.resolve())})
    transport = repository()
    transport.responses[('PUT', 'rulesets/24512048')] = {}
    return receipt, state, journal, transport


def intent(timestamp):
    return json.dumps({'time': timestamp, 'event': 'write_intent', 'operation': 'ruleset',
                       'payload': {**RULE, 'enforcement': 'disabled'}}).encode()+b'\n'


def test_restart_uses_shared_summary_and_original_incident_time(tmp_path, capsys):
    timestamp = datetime.fromtimestamp(time.time()-125, timezone.utc).isoformat()
    receipt, state, journal, transport = prepared_restart(tmp_path, intent(timestamp))
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: transport)
    capture = capsys.readouterr()
    result = json.loads(capture.out)
    assert code == 0 and result['status'] == 'RESTORED'
    assert result['recovery']['attempts'] == 1
    assert result['recovery']['incident'] is True
    assert result['recovery']['time_reliable'] is True
    assert 'RECOVERY_INCIDENT' in capture.err
    assert not (state/'active.json').exists()
    assert all(path != 'pulls/64/merge' for _, path, _ in transport.requests)


@pytest.mark.parametrize('state_value', ['active', 'disabled', 'unavailable'])
def test_no_disable_keeps_active_marker_unless_readback_is_confirmed(tmp_path, capsys, state_value):
    receipt, state, journal, transport = prepared_restart(tmp_path, b'')
    transport.responses[('GET', 'rulesets/24512048')] = (TimeoutError() if state_value == 'unavailable'
                                                      else {**RULE, 'enforcement': state_value})
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: transport)
    result = json.loads(capsys.readouterr().out)
    assert result['recovery']['attempts'] == 0
    assert all(method == 'GET' for method, _, _ in transport.requests)
    if state_value == 'active':
        assert code == 0 and not (state/'active.json').exists()
    else:
        assert code == 2 and result['status'] == 'RECOVERY_REQUIRED'
        assert (state/'active.json').exists()


@pytest.mark.parametrize('raw', [b'{', b'\xff', b'[]\n', b'null\n', b'\n', b'{"event":"observation","number":1e999}\n',
    b'{"event":"write_intent","operation":"ruleset","payload":null}\n',
    b'{"event":"write_intent","operation":"ruleset","payload":"bad"}\n',
    b'{"event":"observation","event":"write_intent"}\n', b'x'*(8*1024**2+1)], ids=['truncated', 'utf8', 'array', 'null', 'blank', 'nonfinite', 'null-payload', 'string-payload', 'duplicate', 'oversized'])
def test_corrupt_events_restore_only_verified_snapshot_and_preserve_raw_evidence(tmp_path, capsys, raw):
    receipt, state, journal, transport = prepared_restart(tmp_path, raw)
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: transport)
    capture = capsys.readouterr()
    result = json.loads(capture.out)
    assert code == 0 and result['restored'] is True
    assert result['recovery']['incident'] is True and result['recovery']['time_reliable'] is False
    assert journal.path.read_bytes() == raw
    assert [path for method, path, _ in transport.requests if method == 'PUT'] == ['rulesets/24512048']
    assert 'RECOVERY_INCIDENT' in capture.err
    assert not (state/'active.json').exists()


def test_corrupt_journal_with_readonly_directory_still_restores(tmp_path, capsys):
    receipt, state, journal, transport = prepared_restart(tmp_path, b'{')
    journal.directory.chmod(0o500)
    try:
        code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                    transport_factory=lambda **kwargs: transport)
    finally:
        journal.directory.chmod(0o700)
    assert [path for method, path, _ in transport.requests if method == 'PUT'] == ['rulesets/24512048']
    assert journal.path.read_bytes() == b'{'
    assert (state/'active.json').exists()  # 最後報告無法落盤時保留現場。 / Keep evidence when result cannot sync.
    assert code == 2


@pytest.mark.parametrize('fault', ['authorization', 'plan', 'snapshot', 'journal-link', 'public-journal'])
def test_corrupt_events_never_bypass_trusted_metadata_or_path_validation(tmp_path, capsys, fault):
    receipt, state, journal, transport = prepared_restart(tmp_path, b'{')
    if fault == 'authorization':
        data = json.loads(receipt.read_text())
        data['authorized'] = False
        receipt.write_text(json.dumps(data))
    elif fault == 'plan':
        data = json.loads((journal.directory/'plan.json').read_text())
        data['pr'] = 65
        (journal.directory/'plan.json').write_text(json.dumps(data))
    elif fault == 'snapshot':
        (journal.directory/'recovery.json').write_text(json.dumps({'ruleset': {**RULE, 'rules': []}}))
    elif fault == 'journal-link':
        target = tmp_path/'external-events'
        target.write_bytes(b'{')
        journal.path.unlink()
        journal.path.symlink_to(target)
    else:
        journal.path.chmod(0o644)
    factories = []
    def factory(**kwargs):
        factories.append(kwargs)
        return transport
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=factory)
    assert code == 2 and factories == [] and transport.requests == []
    assert (state/'active.json').exists()


def test_missing_events_restore_from_verified_snapshot_without_recreating_original(tmp_path, capsys):
    receipt, state, journal, transport = prepared_restart(tmp_path, b'')
    journal.path.unlink()
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: transport)
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result['recovery']['incident'] is True
    assert not journal.path.exists()
    assert [p for m, p, _ in transport.requests if m == 'PUT'] == ['rulesets/24512048']


def test_earliest_intent_wins_even_when_later_event_looks_recent(tmp_path, capsys):
    old = datetime.fromtimestamp(time.time()-125, timezone.utc).isoformat()
    new = datetime.fromtimestamp(time.time()-2, timezone.utc).isoformat()
    receipt, state, journal, transport = prepared_restart(tmp_path, intent(new)+intent(old))
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: transport)
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result['recovery']['incident'] is True
    assert result['recovery']['time_reliable'] is True


@pytest.mark.parametrize('timestamp', [None, 'invalid', '2026-11-02T01:00:00', '2099-01-01T00:00:00+00:00'])
def test_unreliable_intent_time_escalates_but_does_not_block_restore(tmp_path, capsys, timestamp):
    receipt, state, journal, transport = prepared_restart(tmp_path, intent(timestamp))
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: transport)
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result['recovery']['incident'] is True
    assert result['recovery']['time_reliable'] is False


def test_future_intent_among_past_records_makes_timing_unreliable(tmp_path, capsys):
    past = datetime.fromtimestamp(time.time()-30, timezone.utc).isoformat()
    receipt, state, journal, transport = prepared_restart(tmp_path, intent(past)+intent('2099-01-01T00:00:00+00:00'))
    code = main(['--execute', '--recover', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: transport)
    result = json.loads(capsys.readouterr().out)
    assert code == 0 and result['restored'] is True
    assert result['recovery']['incident'] is True
    assert result['recovery']['time_reliable'] is False
