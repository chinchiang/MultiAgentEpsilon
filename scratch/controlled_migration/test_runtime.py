import json
from pathlib import Path
import pytest
from runtime import Journal, ProtectedRemote
from test_migration import GitHub, RULE


def test_recovery_snapshot_and_intent_are_durable_before_first_write(tmp_path):
    journal = Journal(tmp_path / 'run')
    class Inspecting(GitHub):
        def set_ruleset(self, payload):
            saved = json.loads((tmp_path / 'run' / 'recovery.json').read_text())
            assert saved['ruleset'] == RULE
            events = [json.loads(line) for line in (tmp_path / 'run' / 'events.jsonl').read_text().splitlines()]
            assert events[-1]['event'] == 'write_intent'
            super().set_ruleset(payload)
    remote = ProtectedRemote(Inspecting(), journal)
    remote.observe()
    remote.set_ruleset({**RULE, 'enforcement': 'disabled'})
    assert json.loads((tmp_path / 'run' / 'recovery.json').read_text())['ruleset'] == RULE


def test_journal_failure_blocks_disable_but_cannot_block_restore(tmp_path):
    journal = Journal(tmp_path / 'run')
    remote = GitHub()
    protected = ProtectedRemote(remote, journal)
    protected.observe()
    journal.path.unlink()
    journal.path.mkdir()
    with pytest.raises(OSError):
        protected.set_ruleset({**RULE, 'enforcement': 'disabled'})
    assert remote.writes == []
    protected.set_ruleset(RULE)
    assert remote.writes == [RULE]


def test_global_process_lock_refuses_second_coordinator(tmp_path):
    from runtime import ProcessLock
    with ProcessLock(tmp_path / 'coordinator.lock'):
        with pytest.raises(RuntimeError, match='ALREADY_RUNNING'):
            with ProcessLock(tmp_path / 'coordinator.lock'):
                pytest.fail('second writer acquired lock')


def test_readback_logging_failure_does_not_hide_successful_recovery(tmp_path):
    journal = Journal(tmp_path / 'run')
    protected = ProtectedRemote(GitHub(), journal)
    protected.observe()
    journal.path.unlink()
    journal.path.mkdir()
    assert protected.read_ruleset() == RULE


def test_sigterm_becomes_cancellation_inside_protected_execution():
    import os
    import signal
    from runtime import termination_guard
    previous = signal.getsignal(signal.SIGTERM)
    with termination_guard():
        with pytest.raises(KeyboardInterrupt):
            os.kill(os.getpid(), signal.SIGTERM)
    assert signal.getsignal(signal.SIGTERM) == previous


def test_pending_recovery_blocks_new_run_before_transport(tmp_path, capsys):
    from command import main
    state = tmp_path / 'scratch' / 'controlled-migration-state'
    state.mkdir(parents=True)
    (state / 'active.json').write_text('{"directory":"previous-run"}')
    calls = []
    code = main(['--execute'], workspace=tmp_path, transport_factory=lambda **kwargs: calls.append(kwargs))
    assert code != 0
    assert calls == []
    assert 'RECOVERY_REQUIRED' in capsys.readouterr().out


def test_resumed_journal_appends_without_overwriting_recovery_snapshot(tmp_path):
    journal = Journal(tmp_path / 'run')
    journal.save('recovery.json', {'ruleset': RULE})
    journal.record('before_crash')
    resumed = Journal.resume(tmp_path / 'run')
    resumed.record('after_restart')
    assert json.loads((tmp_path / 'run/recovery.json').read_text())['ruleset'] == RULE
    assert [json.loads(line)['event'] for line in (tmp_path / 'run/events.jsonl').read_text().splitlines()] == ['before_crash', 'after_restart']


def workspace_with_receipt(tmp_path):
    import shutil
    import time
    from command import digest, load_plan, tool_digests
    from migration import SCOPE
    source = Path(__file__).parent
    tools = tmp_path/'scratch/controlled_migration'
    tools.mkdir(parents=True)
    for name in ('migration.py', 'command.py', 'github_adapter.py', 'runtime.py'):
        shutil.copyfile(source/name, tools/name)
    plans = tmp_path/'scratch/certifi-controlled-migration-20261102'
    plans.mkdir()
    (plans/'reference-ruleset.json').write_text(json.dumps(RULE))
    plan = load_plan(tmp_path)
    auth = {**SCOPE, 'authorized': True, 'approved_by': 'chinchiang', 'approval_reference': 'OFFLINE TEST ONLY',
            'backup_operator': 'OFFLINE TEST OPERATOR', 'maintenance_freeze_confirmed': True,
            'backup_recovery_confirmed': True, 'expires_at': time.time()+300,
            'plan_sha256': digest(plan), 'tools_sha256': tool_digests(tmp_path)}
    receipt = tmp_path/'receipt.json'
    receipt.write_text(json.dumps(auth))
    receipt.chmod(0o600)
    return plan, auth, receipt


def test_cli_executes_via_external_adapter_and_clears_only_after_restoration(tmp_path, capsys):
    from command import main
    from test_github import repository
    _, _, receipt = workspace_with_receipt(tmp_path)
    transport = repository()
    transport.responses[('PUT', 'rulesets/24512048')] = {}
    transport.responses[('PUT', 'pulls/64/merge')] = {'merged': True}
    original = transport.request
    def request(method, path, payload=None, **kwargs):
        if method == 'PUT' and path == 'rulesets/24512048':
            transport.responses[('GET', path)] = payload
        return original(method, path, payload, **kwargs)
    transport.request = request
    def factory(**kwargs):
        assert kwargs['write_enabled'] is True
        assert isinstance(kwargs['evidence'], Journal)
        return transport
    main(['--execute', '--authorization', str(receipt)], workspace=tmp_path, transport_factory=factory)
    result = json.loads(capsys.readouterr().out)
    assert result['restored'] is True
    assert result['accepted'] is False
    assert not (tmp_path/'scratch/controlled-migration-state/active.json').exists()
    assert transport.responses[('GET', 'rulesets/24512048')] == RULE
    assert sum(method == 'PUT' and path == 'pulls/64/merge' for method, path, _ in transport.requests) == 1
    assert (Path(result['evidence_directory'])/'authorization.json').stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('write_was_attempted', [True, False])
def test_restart_only_restores_and_never_repeats_merge(tmp_path, capsys, write_was_attempted):
    import time
    from command import main
    from runtime import sync_json
    from test_github import repository
    plan, auth, receipt = workspace_with_receipt(tmp_path)
    auth['expires_at'] = time.time()-100  # 到期不妨礙必要恢復。
    receipt.write_text(json.dumps(auth))
    state = tmp_path/'scratch/controlled-migration-state'
    journal = Journal(state/'prior-run')
    for name, value in [('plan.json', plan), ('authorization.json', auth), ('recovery.json', {'ruleset': RULE})]:
        journal.save(name, value)
    if write_was_attempted:
        journal.record('write_intent', operation='ruleset', payload={**RULE, 'enforcement': 'disabled'})
    sync_json(state/'active.json', {'directory': str(journal.directory.resolve())})
    transport = repository()
    transport.responses[('PUT', 'rulesets/24512048')] = {}
    main(['--execute', '--recover', '--authorization', str(receipt)],
         workspace=tmp_path, transport_factory=lambda **kwargs: transport)
    result = json.loads(capsys.readouterr().out)
    writes = [(method, path, payload) for method, path, payload in transport.requests if method == 'PUT']
    assert writes == ([('PUT', 'rulesets/24512048', RULE)] if write_was_attempted else [])
    assert result['restored'] is True
    assert not (state/'active.json').exists()


def test_readonly_outcome_verification_refuses_disabled_protection(tmp_path, capsys):
    from command import main
    from test_github import repository
    workspace_with_receipt(tmp_path)
    transport = repository()
    transport.responses[('GET', 'rulesets/24512048')] = {**RULE, 'enforcement': 'disabled'}
    code = main(['--verify-outcome'], workspace=tmp_path, transport_factory=lambda **kwargs: transport)
    result = json.loads(capsys.readouterr().out)
    assert code != 0
    assert result['status'] == 'BLOCKED'
    assert not any(path == 'pulls/64' for _, path, _ in transport.requests)


@pytest.mark.parametrize('change', ['expired', 'wrong_head', 'unapproved', 'public_file', 'tool_changed'])
def test_receipt_failure_never_creates_remote_adapter(tmp_path, capsys, change):
    import time
    from command import main
    _, auth, receipt = workspace_with_receipt(tmp_path)
    if change == 'expired':
        auth['expires_at'] = time.time()-1
    elif change == 'wrong_head':
        auth['expected_head_sha'] = 'b'*40
    elif change == 'unapproved':
        auth['authorized'] = False
    elif change == 'public_file':
        receipt.chmod(0o644)
    elif change == 'tool_changed':
        (tmp_path/'scratch/controlled_migration/migration.py').write_text('# changed after approval')
    receipt.write_text(json.dumps(auth))
    calls = []
    assert main(['--execute', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: calls.append(kwargs)) != 0
    assert calls == []
    assert not (tmp_path/'scratch/controlled-migration-state/active.json').exists()


def test_first_sigterm_during_restore_keeps_recovery_running():
    import os
    import signal
    from runtime import termination_guard, recovery_signals
    with termination_guard(), recovery_signals():
        os.kill(os.getpid(), signal.SIGTERM)
        with pytest.raises(KeyboardInterrupt):
            os.kill(os.getpid(), signal.SIGTERM)


def test_duplicate_authorization_fields_are_rejected_before_transport(tmp_path, capsys):
    from command import main
    _, _, receipt = workspace_with_receipt(tmp_path)
    receipt.write_text(receipt.read_text().replace('"authorized": true', '"authorized": false, "authorized": true'))
    calls = []
    assert main(['--execute', '--authorization', str(receipt)], workspace=tmp_path,
                transport_factory=lambda **kwargs: calls.append(kwargs)) != 0
    assert calls == []
