import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from security_harness.audit import AuditRun
from security_harness import isolation
from security_harness import supervision
from security_harness.janitor import sweep_stale
from security_harness.lifecycle import supervise
from security_harness.supervision import temporary_directory

ROOT = Path(__file__).resolve().parents[1]


def no_containers(run_id):
    """這些 worker 不建立容器，容器清理換成什麼都不做。 / These workers create no containers, so container cleanup
    does nothing."""


def test_supervised_security_worker_gets_no_token_through_the_gate(tmp_path, monkeypatch):
    # 經過真的 supervise 與 model_process 閘門，觀察 worker 實際收到的環境。 / Through the real supervise and the
    # model_process gate, observe the environment the worker actually receives.
    monkeypatch.setenv('PATH', '/usr/bin:/bin')
    monkeypatch.setenv('GH_TOKEN', 'synthetic-github-token')
    monkeypatch.setenv('GEMINI_API_KEY', 'synthetic-gemini-key')
    audit = AuditRun(tmp_path, 'security')
    audit.stage('G1')
    command = [sys.executable, '-c',
               'import json,os; from pathlib import Path; Path("worker-env.json").write_text(json.dumps(dict(os.environ)))']
    supervise(tmp_path, audit, command, 10, no_containers)
    seen = json.loads((tmp_path / 'worker-env.json').read_text())
    assert seen['PATH'] == '/usr/bin:/bin'
    assert seen['TMPDIR'] == f"/tmp/epsilon-run-{os.getuid()}-{audit.data['run_id']}"
    assert 'GH_TOKEN' not in seen and 'GEMINI_API_KEY' not in seen


def test_deadline_kills_real_child_group_and_removes_tmp(tmp_path, monkeypatch):
    audit = AuditRun(tmp_path, 'security')
    audit.stage('G1')
    command = [sys.executable, '-c',
        'import subprocess,sys,time,tempfile; from pathlib import Path; '
        'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
        'Path("child.pid").write_text(str(p.pid)); '
        'Path(tempfile.gettempdir(),"owned.tmp").write_text("synthetic"); time.sleep(60)']
    assert supervise(tmp_path, audit, command, 0.5, no_containers) == 1
    assert audit.data['execution'] == 'TIMEOUT'
    assert audit.data['records'][0]['execution'] == 'TIMEOUT'
    assert audit.data['cleanup']['completed']
    assert not temporary_directory(audit.data['run_id']).exists()
    child = int((tmp_path / 'child.pid').read_text())
    status = Path(f'/proc/{child}/stat')
    assert not status.exists() or status.read_text().rsplit(')', 1)[1].split()[0] == 'Z'


@pytest.mark.integration
@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGINT, signal.SIGKILL])
def test_real_container_cancel_and_orphan_recovery(tmp_path, signum):
    image = json.loads((ROOT / '.state/runtime-image.json').read_text())['image_id']
    worker = tmp_path / 'worker.py'
    worker.write_text('''import os,sys,tempfile,time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from security_harness.isolation import docker,run_flags
name='epsilon-isolated-'+sys.argv[2].replace('-','')[:16]+'-app'
docker(*run_flags(name,sys.argv[2]),'--user','10001:10001','--entrypoint','python',sys.argv[3],'-c','import time; time.sleep(60)')
Path(tempfile.gettempdir(),'owned.tmp').write_text('synthetic')
Path('ready').write_text(name)
time.sleep(60)
''')
    driver = tmp_path / 'driver.py'
    driver.write_text('''import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from security_harness.audit import AuditRun
from security_harness.lifecycle import supervise
root=Path.cwd(); audit=AuditRun(root,'security'); audit.stage('AUTH')
(root/'run-id').write_text(audit.data['run_id'])
raise SystemExit(supervise(root,audit,[sys.executable,str(root/'worker.py'),sys.argv[1],audit.data['run_id'],sys.argv[2]],30))
''')
    parent = subprocess.Popen([sys.executable, str(driver), str(ROOT), image], cwd=tmp_path,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 15
        while not (tmp_path / 'ready').exists() and time.monotonic() < deadline:
            assert parent.poll() is None
            time.sleep(0.05)
        assert (tmp_path / 'ready').exists()
        run_id = (tmp_path / 'run-id').read_text()
        assert temporary_directory(run_id).exists()
        os.kill(parent.pid, signum)
        parent.wait(timeout=15)
        if signum == signal.SIGKILL:
            assert sweep_stale(tmp_path) == [run_id]
        data = json.loads((tmp_path / 'artifacts' / run_id / 'report.json').read_text())
        assert data['decision'] == 'BLOCK' and data['execution'] == 'CANCELLED'
        assert data['cleanup']['completed']
        assert not temporary_directory(run_id).exists()
        assert not (tmp_path / '.state/runs' / run_id).exists()
        assert not isolation.docker('ps','-aq','--filter','label=epsilon.run='+run_id).stdout.strip()
    finally:
        if parent.poll() is None:
            parent.kill(); parent.wait(timeout=5)
        sweep_stale(tmp_path)


def test_janitor_never_reaps_live_supervisor(tmp_path, monkeypatch):
    from security_harness.lifecycle import cleanup
    from security_harness.supervision import prepare_run
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    audit = AuditRun(tmp_path, 'security')
    work = prepare_run(tmp_path, audit.data['run_id'], 'security')
    assert sweep_stale(tmp_path) == []
    assert work.exists()
    cleanup(tmp_path, audit.data['run_id'])


@pytest.mark.parametrize('execution,code', [('COMPLETED', 0), ('ERROR', 1), ('CANCELLED', 0)])
def test_worker_decision_without_cleanup_handoff_is_not_published(tmp_path, monkeypatch, execution, code):
    audit = AuditRun(tmp_path, 'security')
    report = audit.output / 'report.json'
    command = [sys.executable, '-c',
        'import json,sys; p=sys.argv[1]; d=json.load(open(p)); '
        'd.update(execution=sys.argv[2], decision="ALLOW", reasons=[]); '
        'json.dump(d, open(p, "w")); raise SystemExit(int(sys.argv[3]))', str(report), execution, str(code)]
    assert supervise(tmp_path, audit, command, 10, no_containers) == 1
    assert audit.data['decision'] == 'BLOCK' and audit.data['execution'] == 'ERROR'
    assert audit.data['errors'][-1]['error_type'] == 'RuntimeError'


@pytest.mark.parametrize('tampered', [False, True])
def test_worker_report_that_changes_the_plan_is_blocked_and_restored(tmp_path, monkeypatch, tampered):
    # worker 照常完成清理交接並回報 ALLOW；只要它改了計畫，supervisor 就不得採用。 / The worker completes the cleanup
    # handoff and reports ALLOW as usual; if it changed the plan, the supervisor must not adopt it.
    audit = AuditRun(tmp_path, 'security')
    planned = {'total_seconds': 600, 'cpu_seconds': 300}
    audit.data['resource_limits'] = dict(planned)
    audit.save()
    report = audit.output / 'report.json'
    command = [sys.executable, '-c',
        'import json,sys; p=sys.argv[1]; d=json.load(open(p)); '
        'd["records"]=[{"gate": g, "execution": "COMPLETED"} for g in ("G1", "G2", "AUTH")]; '
        'd.update(execution="AWAITING_CLEANUP", decision="BLOCK", reasons=[], '
        'pending_decision="ALLOW", pending_execution="RUNNING"); '
        'd["resource_limits"]["total_seconds"] += int(sys.argv[2]); '
        'json.dump(d, open(p, "w"))', str(report), str(int(tampered) * 3600)]
    code = supervise(tmp_path, audit, command, 10, no_containers)
    assert audit.data['resource_limits'] == planned
    if tampered:
        assert code == 1 and audit.data['decision'] == 'BLOCK' and audit.data['execution'] == 'ERROR'
        assert audit.data['errors'][-1]['error_type'] == 'PlanMismatch'
    else:
        assert code == 0 and audit.data['decision'] == 'ALLOW' and audit.data['execution'] == 'COMPLETED'


def test_signal_while_closing_the_evidence_still_closes_it_as_blocking(tmp_path):
    # 先前證據在訊號處理器還原、執行清冊刪除之後才關閉；此時的 SIGTERM 會讓證據永遠停在 AWAITING_CLEANUP。 / The
    # evidence used to be closed after the signal handlers were restored and the run inventory removed, so a SIGTERM
    # then left it at AWAITING_CLEANUP forever.
    driver = tmp_path / 'driver.py'
    driver.write_text('''import os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from security_harness.audit import AuditRun
from security_harness.lifecycle import supervise
class SignalledWhileClosing(AuditRun):
    def finish(self,*args,**kwargs):
        if not Path('signalled').exists():
            Path('signalled').touch()
            os.kill(os.getpid(),signal.SIGTERM)
        return super().finish(*args,**kwargs)
root=Path.cwd(); audit=SignalledWhileClosing(root,'security'); audit.stage('AUTH')
(root/'run-id').write_text(audit.data['run_id'])
report=audit.output/'report.json'
worker=[sys.executable,'-c','import json,sys; p=sys.argv[1]; d=json.load(open(p)); '
    'd["records"]=[{"gate": g, "execution": "COMPLETED"} for g in ("G1", "G2", "AUTH")]; '
    'd.update(execution="AWAITING_CLEANUP", decision="BLOCK", reasons=[], pending_decision="ALLOW", '
    'pending_execution="RUNNING"); json.dump(d, open(p, "w"))',str(report)]
raise SystemExit(supervise(root,audit,worker,10,lambda run_id: None))
''')
    result = subprocess.run([sys.executable, str(driver), str(ROOT)], cwd=tmp_path, capture_output=True, timeout=30)
    assert result.returncode == 1, result.stderr
    run_id = (tmp_path / 'run-id').read_text()
    data = json.loads((tmp_path / 'artifacts' / run_id / 'report.json').read_text())
    assert (data['execution'], data['decision']) == ('CANCELLED', 'BLOCK') and 'pending_decision' not in data
    assert data['cleanup']['completed'] and data['cleanup']['process_group_terminated']
    assert (tmp_path / 'artifacts/latest.txt').read_text().strip() == run_id
    assert not (tmp_path / '.state/runs' / run_id).exists() and not temporary_directory(run_id).exists()


def test_worker_that_refuses_the_plan_is_recorded_as_a_plan_mismatch(tmp_path, monkeypatch):
    audit = AuditRun(tmp_path, 'security')
    assert supervise(tmp_path, audit, [sys.executable, '-c', 'raise SystemExit(2)'], 10, no_containers) == 1
    assert audit.data['decision'] == 'BLOCK' and audit.data['execution'] == 'ERROR'
    assert audit.data['errors'][-1]['error_type'] == 'PlanMismatch'


def test_security_worker_with_another_plan_exits_without_touching_the_report(tmp_path):
    import shutil
    # 複製來源樹，讓 worker 的 ROOT 指向暫存目錄。 / Copy the source trees so the worker's ROOT is the temporary directory.
    for folder in ('scripts', 'security_harness', 'security'):
        shutil.copytree(ROOT / folder, tmp_path / folder, ignore=shutil.ignore_patterns('__pycache__'))
    audit = AuditRun(tmp_path, 'security')
    audit.data['resource_limits'] = {'total_seconds': 600}
    audit.save()
    report = audit.output / 'report.json'
    before = report.read_bytes()
    result = subprocess.run([sys.executable, '-I', str(tmp_path / 'scripts/security_worker.py'), audit.data['run_id'],
                             '0' * 64], cwd=tmp_path, capture_output=True, timeout=30)
    assert result.returncode == 2, result.stderr
    assert report.read_bytes() == before


@pytest.mark.parametrize('deadline', [0, -1, True, float('nan'), float('inf'), 601])
def test_invalid_security_deadline_never_launches(tmp_path, deadline):
    with pytest.raises(ValueError, match='^invalid supervisor deadline$'):
        supervise(tmp_path, AuditRun(tmp_path, 'security'), ['must-not-execute'], deadline)
    assert not (tmp_path / '.state').exists()


def test_security_worker_is_registered_durably_before_it_runs(tmp_path, monkeypatch):
    # worker 一開始就看得到自己的登記；擁有者標記不再記錄 worker。 / The worker already sees its own registration when it
    # starts; the owner marker no longer records the worker.
    command = [sys.executable, '-c',
               'import json,os,pathlib; runs=pathlib.Path(".state/runs"); '
               'pathlib.Path("seen.json").write_text(json.dumps({"pid": os.getpid(), '
               '"groups": [json.loads(p.read_text()) for p in runs.glob("*/groups/*.json")], '
               '"owners": [json.loads(p.read_text()) for p in runs.glob("*/owner.json")]}))']
    supervise(tmp_path, AuditRun(tmp_path, 'security'), command, 10, no_containers)
    seen = json.loads((tmp_path / 'seen.json').read_text())
    assert [(g['pid'], g['role']) for g in seen['groups']] == [(seen['pid'], 'worker')]
    assert [o['operation'] for o in seen['owners']] == ['security'] and 'worker_pid' not in seen['owners'][0]


def test_janitor_stops_the_registered_worker_group_of_a_dead_security_supervisor(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    audit = AuditRun(tmp_path, 'security')
    work = supervision.prepare_run(tmp_path, audit.data['run_id'], 'security')
    worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
    try:
        supervision.register_group(work, worker.pid, role='worker')
        monkeypatch.setattr(supervision, 'owner_alive', lambda marker: False)
        assert sweep_stale(tmp_path) == [audit.data['run_id']]
        assert worker.wait(timeout=5) is not None
        assert json.loads((audit.output / 'report.json').read_text())['execution'] == 'CANCELLED'
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=5)


def test_janitor_keeps_latest_pointer_on_the_newer_run(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    stale = AuditRun(tmp_path, 'security')
    supervision.prepare_run(tmp_path, stale.data['run_id'], 'security')
    newer = AuditRun(tmp_path, 'security')
    newer.finish()
    monkeypatch.setattr(supervision, 'owner_alive', lambda marker: False)
    assert sweep_stale(tmp_path) == [stale.data['run_id']]
    assert json.loads((stale.output / 'report.json').read_text())['execution'] == 'CANCELLED'
    assert (tmp_path / 'artifacts/latest.txt').read_text().strip() == newer.data['run_id']


class FakeDocker:
    """Docker CLI 邊界的假實作，只認得 janitor 需要的 ps／inspect／rm。 / Fake Docker CLI boundary for the janitor's ps/inspect/rm."""

    def __init__(self, *containers, rm_fails=False):
        self.containers = {c['Id']: c for c in containers}
        self.removed = []
        self.rm_fails = rm_fails

    def __call__(self, *args, check=True, timeout=45):
        if args[:2] == ('ps', '-aq') and 'label=epsilon.isolated=true' in args:
            out = ''.join(i + '\n' for i in self.containers)
        elif args[0] == 'inspect':
            out = json.dumps([self.containers[i] for i in args[1:]])
        elif args[:2] == ('rm', '--force'):
            if self.rm_fails:
                raise subprocess.CalledProcessError(1, args)
            self.removed.extend(args[2:])
            out = ''
        else:
            pytest.fail('unexpected docker call: ' + ' '.join(args))
        return subprocess.CompletedProcess(args, 0, out, '')


def container(identifier, run_id, minutes_old):
    created = time.strftime('%Y-%m-%dT%H:%M:%S.123456789Z', time.gmtime(time.time() - minutes_old * 60))
    labels = {'epsilon.isolated': 'true'} | ({'epsilon.run': run_id} if run_id is not None else {})
    return {'Id': identifier, 'Created': created, 'Config': {'Labels': labels}}


def test_janitor_removes_a_container_created_after_its_run_was_cleaned(tmp_path, monkeypatch):
    # daemon 很慢時，容器可能在 cleanup 刪除 run 目錄之後才出現。 / A slow daemon can create a container after cleanup removed its run.
    fake = FakeDocker(container('late', 'a' * 32, minutes_old=11))
    monkeypatch.setattr(isolation, 'docker', fake)
    assert sweep_stale(tmp_path) == []
    assert fake.removed == ['late']


def test_janitor_keeps_a_young_container_that_another_checkout_may_own(tmp_path, monkeypatch):
    fake = FakeDocker(container('young', 'b' * 32, minutes_old=9), container('old', 'c' * 32, minutes_old=11))
    monkeypatch.setattr(isolation, 'docker', fake)
    sweep_stale(tmp_path)
    assert fake.removed == ['old']


def test_janitor_keeps_an_old_container_of_a_live_run(tmp_path, monkeypatch):
    from security_harness.lifecycle import cleanup
    from security_harness.supervision import prepare_run
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    audit = AuditRun(tmp_path, 'security')
    prepare_run(tmp_path, audit.data['run_id'], 'security')
    fake = FakeDocker(container('live', audit.data['run_id'], minutes_old=11))
    monkeypatch.setattr(isolation, 'docker', fake)
    assert sweep_stale(tmp_path) == []
    assert fake.removed == []
    cleanup(tmp_path, audit.data['run_id'])


def test_janitor_reports_a_failed_container_sweep_without_losing_reaped_runs(tmp_path, monkeypatch):
    from security_harness.janitor import SweepIncomplete
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    stale = AuditRun(tmp_path, 'security')
    supervision.prepare_run(tmp_path, stale.data['run_id'], 'security')
    monkeypatch.setattr(supervision, 'owner_alive', lambda marker: False)
    monkeypatch.setattr(isolation, 'docker', FakeDocker(container('stuck', 'd' * 32, minutes_old=11), rm_fails=True))
    with pytest.raises(SweepIncomplete) as raised:
        sweep_stale(tmp_path)
    assert raised.value.cleaned == [stale.data['run_id']]
    assert raised.value.failures == [{'containers': 'epsilon.isolated', 'error_type': 'CalledProcessError'}]


def test_required_gates_follow_the_trusted_policy(tmp_path):
    import json as _json
    from security_harness.results import DEFAULT_GATES, required_gate_kinds
    root = Path(__file__).resolve().parents[1]
    policy = _json.loads((root / "security/policy.json").read_text())
    assert required_gate_kinds(root) == tuple((g, policy["gate_contracts"][g]["kind"]) for g in policy["required_gates"])
    assert required_gate_kinds(root) == DEFAULT_GATES  # 備援必須與目前政策一致。 / The fallback must match today's policy.
    assert required_gate_kinds(tmp_path) == DEFAULT_GATES


def test_missing_gate_at_finish_turns_an_earlier_allow_into_block(tmp_path):
    from security_harness.audit import AuditRun
    audit = AuditRun(tmp_path, "security")
    audit.data.update(decision="ALLOW", reasons=[])
    assert audit.finish((("G1", "scan"),)) == 1
    assert audit.data["decision"] == "BLOCK" and audit.data["records"][0]["execution"] == "NOT_RUN"
    assert (tmp_path / "artifacts/latest.txt").read_text() == audit.data["run_id"] + "\n"
    assert not list((tmp_path / "artifacts").glob(".pointer-*"))


def test_failure_is_persisted_immediately(tmp_path):
    import json as _json
    from security_harness.audit import AuditRun
    audit = AuditRun(tmp_path, "security")
    audit.fail(RuntimeError("secret text must not be stored"))
    saved = _json.loads((audit.output / "report.json").read_text())
    assert saved["execution"] == "ERROR" and saved["errors"] == [{"stage": "initialization", "error_type": "RuntimeError"}]
    assert "secret text" not in (audit.output / "report.json").read_text()


@pytest.mark.parametrize("run_id", ["-" * 36, "a" * 33, "A" * 32, "../" + "a" * 29, "a" * 8 + "-" * 28, None])
def test_run_identity_accepts_only_hex_or_canonical_uuid(run_id):
    from security_harness.isolation import cleanup_run
    from security_harness.supervision import run_directory, valid_run_id
    assert not valid_run_id(run_id)
    with pytest.raises((ValueError, TypeError), match='^invalid\\ run\\ identity$'):
        run_directory(Path("/tmp"), run_id)
    with pytest.raises((ValueError, TypeError), match='^invalid\\ isolation\\ run\\ ID$'):
        cleanup_run(run_id)


def test_generated_run_identities_remain_valid():
    import secrets
    import uuid
    from security_harness.supervision import valid_run_id
    assert valid_run_id(str(uuid.uuid4())) and valid_run_id(secrets.token_hex(16))
