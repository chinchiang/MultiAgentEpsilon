"""真實程序崩潰與持久化復原，不需 Docker、金鑰或網路。

Real process crashes and durable recovery; no Docker, keys or network needed."""
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from scripts.model_smoke import initial_report
from security_harness.lifecycle import prepare_run, sweep_stale, temporary_directory
from security_harness.llm import lifecycle as life

ROOT = Path(__file__).resolve().parents[1]


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    pytest.fail('process fixture did not reach the required state')


def alive(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z'
    except FileNotFoundError:
        return False


def setup_driver(tmp_path, *, hang=True, timeout=20, pause=None, child_registration=False):
    aws = tmp_path / 'aws-fixture'
    aws.write_text(f'#!{sys.executable}\n' + '''import json,os,signal,subprocess,sys,time
from pathlib import Path
payload=json.loads(Path(sys.argv[sys.argv.index('--cli-input-json')+1].removeprefix('file://')).read_text())
assert payload['messages'][0]['content'][0]['text'].startswith('Reply with exactly')
temp=Path(os.environ['TMPDIR'])/'nested';temp.mkdir();(temp/'owned.tmp').write_text('synthetic')
child=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
Path('aws-pids').write_text(str(os.getpid())+' '+str(child.pid))
''' + ('''signal.signal(signal.SIGTERM,signal.SIG_IGN)
time.sleep(60)
''' if hang else '''print(json.dumps({'output':{'message':{'role':'assistant','content':[{'text':'EPSILON_SYNTHETIC_OK'}]}},'stopReason':'end_turn'}))
'''))
    aws.chmod(0o700)
    worker = ROOT / 'scripts/model_worker.py'
    if child_registration:
        worker = tmp_path / 'worker.py'
        worker.write_text(f'''import asyncio,sys,time
from pathlib import Path
sys.path.insert(0,{str(ROOT)!r})
from security_harness.llm import lifecycle as life
from scripts.model_smoke import run_worker
def paused_register(work,pid,role='child'):
    Path('gated-child').write_text(str(pid))
    time.sleep(60)
life.register_group=paused_register
raise SystemExit(asyncio.run(run_worker(Path.cwd(),sys.argv[2])))
''')
    driver = tmp_path / 'driver.py'
    driver.write_text(f'''import os,sys,time,uuid
from pathlib import Path
sys.path.insert(0,{str(ROOT)!r})
from scripts.model_smoke import initial_report
from security_harness.llm import lifecycle as life
root=Path.cwd(); run_id=str(uuid.uuid4())
report=initial_report(['bedrock','mock'],run_id)
life.persist(root/'artifacts'/run_id/'report.json',report)
Path('run-id').write_text(run_id)
pause={pause!r}
if pause=='registration':
    def delayed(work,pid,role='child'):
        Path('gated-worker').write_text(str(pid))
        time.sleep(60)
    life.register_group=delayed
if pause=='finish':
    original=life.finish
    def delayed(*args,**kwargs):
        Path('awaiting-cleanup').touch()
        time.sleep(60)
        return original(*args,**kwargs)
    life.finish=delayed
data=life.supervise(root,report,[sys.executable,'-I',{str(worker)!r},str(root),run_id],{timeout})
raise SystemExit(0 if data['status']=='COMPLETE' else 1)
''')
    env = {**os.environ, 'BEDROCK_MODEL_ID': 'synthetic-profile', 'BEDROCK_REGION': 'ap-southeast-1',
           'AWS_CLI_PATH': str(aws)}
    process = subprocess.Popen([sys.executable, '-I', str(driver)], cwd=tmp_path, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return process


def report_at(root):
    run_id = (root / 'run-id').read_text()
    return json.loads((root / 'artifacts' / run_id / 'report.json').read_text())


def assert_clean(root, data):
    assert data['cleanup']['completed']
    assert data['cleanup']['process_groups_terminated']
    assert not (root / '.state/runs' / data['run_id']).exists()
    assert not temporary_directory(data['run_id']).exists()
    for name in ('aws-pids', 'gated-child', 'gated-worker'):
        if (root / name).exists():
            wait_for(lambda: all(not alive(int(pid)) for pid in (root / name).read_text().split()))


def teardown_driver(root, parent):
    if parent.poll() is None:
        parent.kill()
        parent.wait(timeout=5)
    sweep_stale(root)


@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGINT, signal.SIGKILL])
def test_parent_cancellation_and_sigkill_reap_real_aws_group(tmp_path, signum):
    parent = setup_driver(tmp_path)
    try:
        wait_for(lambda: (tmp_path / 'aws-pids').exists())
        assert report_at(tmp_path)['status'] == 'INCOMPLETE'
        assert sweep_stale(tmp_path) == []  # 不可碰觸仍存活的擁有者。 / Never touch an active owner.
        parent.send_signal(signum)
        parent.wait(timeout=10)
        if signum == signal.SIGKILL:
            assert sweep_stale(tmp_path) == [(tmp_path / 'run-id').read_text()]
        data = report_at(tmp_path)
        assert data['status'] == 'CANCELLED'
        assert data['checks'][0]['status'] == 'CANCELLED'
        assert data['checks'][1]['status'] == 'NOT_RUN'
        assert_clean(tmp_path, data)
        assert sweep_stale(tmp_path) == []
    finally:
        teardown_driver(tmp_path, parent)


def test_worker_sigkill_cannot_orphan_aws_or_publish_success(tmp_path):
    parent = setup_driver(tmp_path)
    try:
        wait_for(lambda: (tmp_path / 'aws-pids').exists())
        run_id = (tmp_path / 'run-id').read_text()
        groups = [json.loads(p.read_text()) for p in (tmp_path / '.state/runs' / run_id / 'groups').glob('*.json')]
        worker = next(g for g in groups if g['role'] == 'worker')
        os.kill(worker['pid'], signal.SIGKILL)
        assert parent.wait(timeout=10) == 1
        data = report_at(tmp_path)
        assert data['status'] == 'INCOMPLETE' and data['code'] == 'WORKER_FAILED'
        assert data['checks'][0]['status'] == 'ERROR'
        assert_clean(tmp_path, data)
    finally:
        teardown_driver(tmp_path, parent)


def test_total_deadline_kills_term_ignoring_cli_descendant(tmp_path):
    parent = setup_driver(tmp_path, timeout=1.5)
    try:
        assert parent.wait(timeout=10) == 1
        data = report_at(tmp_path)
        assert data['status'] == 'TIMEOUT'
        assert_clean(tmp_path, data)
    finally:
        teardown_driver(tmp_path, parent)


def test_success_is_only_published_after_cleanup(tmp_path):
    parent = setup_driver(tmp_path, hang=False)
    try:
        assert parent.wait(timeout=10) == 0
        data = report_at(tmp_path)
        assert data['status'] == 'COMPLETE' and len(data['calls']) == 2
        assert_clean(tmp_path, data)
    finally:
        teardown_driver(tmp_path, parent)


def test_kill_after_worker_success_never_promotes_pending_success(tmp_path):
    parent = setup_driver(tmp_path, hang=False, pause='finish')
    try:
        wait_for(lambda: (tmp_path / 'awaiting-cleanup').exists())
        assert report_at(tmp_path)['status'] == 'AWAITING_CLEANUP'
        parent.kill(); parent.wait(timeout=5)
        sweep_stale(tmp_path)
        data = report_at(tmp_path)
        assert data['status'] == 'CANCELLED' and 'pending_status' not in data
        assert_clean(tmp_path, data)
    finally:
        teardown_driver(tmp_path, parent)


@pytest.mark.parametrize('child_registration', [False, True])
def test_kill_before_registration_cannot_execute_untracked_child(tmp_path, child_registration):
    parent = setup_driver(tmp_path, pause=None if child_registration else 'registration',
                          child_registration=child_registration)
    try:
        name = 'gated-child' if child_registration else 'gated-worker'
        wait_for(lambda: (tmp_path / name).exists())
        parent.kill(); parent.wait(timeout=5)
        sweep_stale(tmp_path)
        assert not (tmp_path / 'aws-pids').exists()
        data = report_at(tmp_path)
        assert data['status'] == 'CANCELLED'
        assert_clean(tmp_path, data)
    finally:
        teardown_driver(tmp_path, parent)


def stale_fixture(root):
    run_id = str(uuid.uuid4())
    data = initial_report(['mock'], run_id)
    path = root / 'artifacts' / run_id / 'report.json'
    life.persist(path, data)
    work = prepare_run(root, run_id, operation='model-smoke')
    marker = json.loads((work / 'owner.json').read_text())
    marker['boot'] = 'previous-boot'
    life.persist(work / 'owner.json', marker)
    return run_id, path, work


@pytest.mark.parametrize('corruption', ['missing', 'invalid-json', 'wrong-run', 'invalid-records', 'duplicate-key'])
def test_missing_or_corrupt_evidence_recovered_as_cancelled(tmp_path, corruption):
    run_id, path, work = stale_fixture(tmp_path)
    if corruption == 'missing':
        path.unlink()
    elif corruption == 'invalid-json':
        path.write_text('private raw failure must not be copied')
    elif corruption == 'duplicate-key':
        path.write_text(path.read_text().replace('"status": "INCOMPLETE"', '"status": "INCOMPLETE", "status": "COMPLETE"'))
    else:
        data = json.loads(path.read_text())
        data['status'] = 'COMPLETE'
        data['run_id' if corruption == 'wrong-run' else 'checks'] = None
        life.persist(path, data)
    assert sweep_stale(tmp_path) == [run_id]
    data = json.loads(path.read_text())
    assert data['status'] == 'CANCELLED'
    assert data['evidence_error'] == 'EVIDENCE_INVALID'
    assert 'private raw' not in path.read_text()
    assert_clean(tmp_path, data)


def test_cleanup_failure_blocks_and_preserves_recovery_inventory(tmp_path, monkeypatch):
    run_id, path, work = stale_fixture(tmp_path)
    original = life.stop_registered
    def failure(_):
        raise RuntimeError('sensitive CLI diagnostics')
    monkeypatch.setattr(life, 'stop_registered', failure)
    with pytest.raises(RuntimeError):
        sweep_stale(tmp_path)
    data = json.loads(path.read_text())
    assert data['status'] == 'ERROR' and data['code'] == 'CLEANUP_FAILED'
    assert not data['cleanup']['completed'] and work.exists()
    assert 'sensitive CLI' not in path.read_text()
    monkeypatch.setattr(life, 'stop_registered', original)
    assert sweep_stale(tmp_path) == [run_id]
    assert_clean(tmp_path, json.loads(path.read_text()))


def test_one_unrecoverable_run_does_not_strand_the_others(tmp_path, monkeypatch):
    from security_harness.lifecycle import SweepIncomplete
    runs = sorted([stale_fixture(tmp_path), stale_fixture(tmp_path)])
    (broken, broken_path, broken_work), (healthy, healthy_path, _) = runs  # 依 run ID 順序回收。 / sweep order is by run ID
    original = life.stop_registered
    def selective(work):
        if work.name == broken:
            raise RuntimeError('sensitive CLI diagnostics')
        return original(work)
    monkeypatch.setattr(life, 'stop_registered', selective)
    with pytest.raises(SweepIncomplete) as raised:
        sweep_stale(tmp_path)
    assert raised.value.cleaned == [healthy]
    assert raised.value.failures == [{'run_id': broken, 'error_type': 'RuntimeError'}]
    assert 'sensitive' not in str(raised.value.failures)
    assert_clean(tmp_path, json.loads(healthy_path.read_text()))
    assert broken_work.exists() and json.loads(broken_path.read_text())['code'] == 'CLEANUP_FAILED'
    monkeypatch.setattr(life, 'stop_registered', original)
    assert sweep_stale(tmp_path) == [broken]
    assert_clean(tmp_path, json.loads(broken_path.read_text()))


@pytest.mark.parametrize('change', ['boot', 'start'])
def test_janitor_does_not_signal_different_boot_or_reused_pid(tmp_path, change):
    run_id, path, work = stale_fixture(tmp_path)
    other = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
    try:
        group = {'pid': other.pid, 'uid': os.getuid(), 'start': life.identity(other.pid),
                 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'role': 'child'}
        group[change] = 'not-the-current-identity'
        life.persist(work / 'groups' / f'{other.pid}.json', group)
        sweep_stale(tmp_path)
        assert other.poll() is None
    finally:
        other.kill(); other.wait(timeout=5)


def test_cleanup_lock_prevents_two_janitors_from_reaping_same_run(tmp_path):
    run_id, path, work = stale_fixture(tmp_path)
    with life.cleanup_lock(work) as locked:
        assert locked and sweep_stale(tmp_path) == []
        assert work.exists()
    assert sweep_stale(tmp_path) == [run_id]


def test_signal_during_cleanup_cannot_publish_complete(tmp_path, monkeypatch):
    run_id = str(uuid.uuid4())
    report = initial_report(['mock'], run_id)
    life.persist(tmp_path / 'artifacts' / run_id / 'report.json', report)
    original = life.stop_registered
    def cancel_during_cleanup(work):
        os.kill(os.getpid(), signal.SIGTERM)
        original(work)
    monkeypatch.setattr(life, 'stop_registered', cancel_during_cleanup)
    data = life.supervise(tmp_path, report, [sys.executable, '-I', str(ROOT / 'scripts/model_worker.py'),
                                           str(tmp_path), run_id], 10)
    assert data['status'] == 'CANCELLED'
    assert_clean(tmp_path, data)


def test_worker_wait_timeout_still_finalizes_evidence(tmp_path, monkeypatch):
    # 先前 reap 逾時會在 finish 前逸出，留下 AWAITING_CLEANUP / A reap timeout used to escape before finish(), leaving AWAITING_CLEANUP evidence
    # 以及尚未還原的訊號處理器。 / and the signal handlers installed.
    run_id = str(uuid.uuid4())
    report = initial_report(['mock'], run_id)
    life.persist(tmp_path / 'artifacts' / run_id / 'report.json', report)
    original_wait = subprocess.Popen.wait
    raised = []
    def stubborn(self, timeout=None):
        if not raised and timeout == 5:
            raised.append(True)
            raise subprocess.TimeoutExpired(self.args, timeout)
        return original_wait(self, timeout=timeout)
    monkeypatch.setattr(subprocess.Popen, 'wait', stubborn)
    handler = signal.getsignal(signal.SIGTERM)
    data = life.supervise(tmp_path, report, [sys.executable, '-I', str(ROOT / 'scripts/model_worker.py'),
                                           str(tmp_path), run_id], 10)
    assert raised and data['status'] not in ('COMPLETE', 'AWAITING_CLEANUP') and 'pending_status' not in data
    assert signal.getsignal(signal.SIGTERM) is handler
    assert_clean(tmp_path, data)


@pytest.mark.parametrize('deadline', [0, -1, True, float('nan'), float('inf'), 131])
def test_invalid_supervisor_deadline_never_launches(tmp_path, deadline):
    report = initial_report(['mock'], str(uuid.uuid4()))
    with pytest.raises(ValueError):
        life.supervise(tmp_path, report, ['must-not-execute'], deadline)
    assert not (tmp_path / '.state').exists()


@pytest.mark.parametrize('mutation', ['empty', 'missing-call', 'wrong-exit', 'direct-complete'])
def test_forged_completion_is_not_accepted(mutation):
    data = initial_report(['mock'], str(uuid.uuid4()))
    data.update(status='AWAITING_CLEANUP', pending_status='COMPLETE',
                checks=[{'provider': 'mock', 'status': 'SUCCESS'}],
                calls=[{'provider': 'mock', 'status': 'SUCCESS'}])
    code, providers = 0, ['mock']
    if mutation == 'empty':
        data.update(providers=[], checks=[], calls=[]); providers=[]
    elif mutation == 'missing-call':
        data['calls'] = []
    elif mutation == 'wrong-exit':
        code = -9
    else:
        data['status'] = 'COMPLETE'
    assert not life.complete_worker_report(data, providers, code)
