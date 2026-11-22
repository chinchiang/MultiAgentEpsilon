"""子程序閘門協定的直接測試：先登記程序群組、再放行；不啟動真實程序，可在突變快照內執行。

Direct tests of the subprocess gate protocol: register the process group first, release it afterwards. No real
process is started, so they run in the mutation snapshot."""
import json
import os
import subprocess
import sys

import pytest

from security_harness import supervision

PID = 4242


class Stdin:
    def __init__(self):
        self.written, self.closed, self.flushed = [], 0, 0

    def write(self, data):
        self.written.append(data)

    def close(self):
        self.closed += 1

    def flush(self):
        self.flushed += 1


class Process:
    def __init__(self, stdin=True, text_mode=False):
        self.pid, self.stdin, self.text_mode = PID, Stdin() if stdin else None, text_mode


def inventory(tmp_path, uid=None):
    work = tmp_path / 'run'
    (work / 'groups').mkdir(parents=True)
    (work / 'owner.json').write_text(json.dumps({'uid': os.getuid() if uid is None else uid, 'boot': 'boot-1'}))
    return work


def session(monkeypatch, sid=PID, pgid=PID):
    saved = []
    monkeypatch.setattr(supervision.os, 'getsid', lambda pid: sid)
    monkeypatch.setattr(supervision.os, 'getpgid', lambda pid: pgid)
    monkeypatch.setattr(supervision, 'identity', lambda pid: 'start-7')
    monkeypatch.setattr(supervision, 'persist', lambda path, data: saved.append((path, data)))
    return saved


def test_a_dedicated_session_leader_is_registered_with_its_identity(tmp_path, monkeypatch):
    work, saved = inventory(tmp_path), session(monkeypatch)
    supervision.register_group(work, PID, role='worker')
    assert saved == [(work / 'groups' / f'{PID}.json',
                      {'pid': PID, 'start': 'start-7', 'boot': 'boot-1', 'uid': os.getuid(), 'role': 'worker'})]


def test_an_inventory_owned_by_another_user_registers_nothing(tmp_path, monkeypatch):
    work, saved = inventory(tmp_path, uid=os.getuid() + 1), session(monkeypatch)
    with pytest.raises(ValueError, match='^invalid run owner$'):
        supervision.register_group(work, PID)
    assert saved == []


@pytest.mark.parametrize('sid,pgid', [(PID + 1, PID), (PID, PID + 1), (PID + 1, PID + 1)])
def test_a_child_that_does_not_lead_its_own_session_and_group_is_refused(tmp_path, monkeypatch, sid, pgid):
    # 群組終止以 pid 當群組編號；子程序不是自己 session 與群組的首領時，終止會打到別人。 / Group termination uses the
    # pid as the group id, so a child that leads neither its session nor its group would get someone else killed.
    work, saved = inventory(tmp_path), session(monkeypatch, sid, pgid)
    with pytest.raises(ValueError, match='^supervised child requires a dedicated session$'):
        supervision.register_group(work, PID)
    assert saved == []


def registrations(monkeypatch):
    calls = []
    monkeypatch.setattr(supervision, 'register_group', lambda work, pid, role='child': calls.append((work, pid, role)))
    return calls


def test_release_registers_before_it_writes_the_gate_byte(tmp_path, monkeypatch):
    order, process = [], Process()
    monkeypatch.setattr(supervision, 'register_group', lambda work, pid, role='child': order.append(('register', work, pid, role)))
    process.stdin.write = lambda data: order.append(('write', data))
    process.stdin.close = lambda: order.append(('close',))
    supervision.release_gated_group(tmp_path, process, role='worker')
    assert order == [('register', tmp_path, PID, 'worker'), ('write', b'G'), ('close',)]


def test_release_without_an_inventory_registers_nothing_but_still_releases(monkeypatch):
    calls, process = registrations(monkeypatch), Process(text_mode=True)
    supervision.release_gated_group(None, process)
    assert calls == [] and process.stdin.written == ['G'] and process.stdin.closed == 1


def test_release_of_an_ungated_command_sends_no_gate_byte(monkeypatch):
    calls, process = registrations(monkeypatch), Process()
    supervision.release_gated_group(None, process, gated=False)
    assert calls == [] and process.stdin.written == [] and process.stdin.closed == 1


def test_release_can_leave_stdin_open_for_the_caller(tmp_path, monkeypatch):
    calls, process = registrations(monkeypatch), Process()
    supervision.release_gated_group(tmp_path, process, close_stdin=False)
    assert calls == [(tmp_path, PID, 'child')]
    assert (process.stdin.written, process.stdin.closed, process.stdin.flushed) == ([b'G'], 0, 1)


def test_release_of_a_process_without_stdin_only_registers(tmp_path, monkeypatch):
    calls = registrations(monkeypatch)
    supervision.release_gated_group(tmp_path, Process(stdin=False))
    assert calls == [(tmp_path, PID, 'child')]


def test_gated_command_wraps_the_command_and_an_ungated_one_is_only_copied():
    command = ['tool', '--flag']
    gated = supervision.gated_command(command)
    assert gated[0] == sys.executable and gated[1] == '-I' and gated[2].endswith('scripts/model_process.py')
    assert gated[3:] == command
    plain = supervision.gated_command(command, gated=False)
    assert plain == command and plain is not command


class Popen:
    """假的 Popen：記下呼叫並回傳預先設定的輸出，或在 communicate 丟出例外。 / A fake Popen recording its calls and
    returning preset output, or raising from communicate."""
    instances = []

    def __init__(self, command, **options):
        self.command, self.options, self.pid, self.returncode = command, options, PID, 0
        self.stdin, self.text_mode, self.events = Stdin(), options.get('text', False), []
        self.failure = None
        Popen.instances.append(self)

    def communicate(self, timeout=None):
        self.events.append(('communicate', timeout))
        if self.failure is not None and len([e for e in self.events if e[0] == 'communicate']) == 1:
            raise self.failure
        return 'out', 'err'

    def kill(self):
        self.events.append(('kill',))


@pytest.fixture
def popen(monkeypatch):
    Popen.instances = []
    monkeypatch.setattr(supervision.subprocess, 'Popen', Popen)
    return Popen


def test_gated_subprocess_without_a_run_registers_nothing_and_returns_the_output(tmp_path, monkeypatch, popen):
    calls = registrations(monkeypatch)
    monkeypatch.setattr(supervision, 'run_directory', lambda root, run_id: pytest.fail('no run id was given'))
    done = supervision.run_gated_subprocess(['tool'], 7, root=tmp_path)
    process = popen.instances[0]
    assert process.command == supervision.gated_command(['tool'])
    assert process.options['start_new_session'] is True and process.options['cwd'] == tmp_path
    assert calls == [] and process.stdin.written == ['G'] and process.stdin.closed == 0
    assert process.events == [('communicate', 7)]
    assert (done.args, done.returncode, done.stdout, done.stderr) == (['tool'], 0, 'out', 'err')


def test_gated_subprocess_registers_in_an_owned_run_inventory_before_release(tmp_path, monkeypatch, popen):
    work, calls = inventory(tmp_path), registrations(monkeypatch)
    monkeypatch.setattr(supervision, 'run_directory', lambda root, run_id: work)
    supervision.run_gated_subprocess(['tool'], 7, root=tmp_path, run_id='a' * 32, role='worker')
    assert calls == [(work, PID, 'worker')] and popen.instances[0].stdin.written == ['G']


def test_gated_subprocess_skips_registration_when_the_run_has_no_owner_marker(tmp_path, monkeypatch, popen):
    calls = registrations(monkeypatch)
    monkeypatch.setattr(supervision, 'run_directory', lambda root, run_id: tmp_path / 'absent')
    supervision.run_gated_subprocess(['tool'], 7, root=tmp_path, run_id='a' * 32)
    assert calls == [] and popen.instances[0].stdin.written == ['G']


def test_gated_subprocess_terminates_the_whole_group_and_reraises_on_timeout(tmp_path, monkeypatch, popen):
    registrations(monkeypatch)
    terminated = []
    monkeypatch.setattr(supervision, 'terminate_group', lambda pid: terminated.append(pid))
    original = popen.__init__

    def failing(self, command, **options):
        original(self, command, **options)
        self.failure = subprocess.TimeoutExpired(command, 7)
    monkeypatch.setattr(popen, '__init__', failing)
    with pytest.raises(subprocess.TimeoutExpired):
        supervision.run_gated_subprocess(['tool'], 7, root=tmp_path)
    assert terminated == [PID]
    assert popen.instances[0].events == [('communicate', 7), ('kill',), ('communicate', 5)]
