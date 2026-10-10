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
from security_harness.lifecycle import supervise, temporary_directory, sweep_stale

ROOT = Path(__file__).resolve().parents[1]


def test_deadline_kills_real_child_group_and_removes_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    audit = AuditRun(tmp_path, 'security')
    audit.stage('G1')
    command = [sys.executable, '-c',
        'import subprocess,sys,time,tempfile; from pathlib import Path; '
        'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
        'Path("child.pid").write_text(str(p.pid)); '
        'Path(tempfile.gettempdir(),"owned.tmp").write_text("synthetic"); time.sleep(60)']
    assert supervise(tmp_path, audit, command, 0.5) == 1
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
    from security_harness.lifecycle import prepare_run, cleanup
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    audit = AuditRun(tmp_path, 'security')
    work = prepare_run(tmp_path, audit.data['run_id'])
    assert sweep_stale(tmp_path) == []
    assert work.exists()
    cleanup(tmp_path, audit.data['run_id'])


@pytest.mark.parametrize('execution,code', [('COMPLETED', 0), ('ERROR', 1), ('CANCELLED', 0)])
def test_worker_decision_without_cleanup_handoff_is_not_published(tmp_path, monkeypatch, execution, code):
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    audit = AuditRun(tmp_path, 'security')
    report = audit.output / 'report.json'
    command = [sys.executable, '-c',
        'import json,sys; p=sys.argv[1]; d=json.load(open(p)); '
        'd.update(execution=sys.argv[2], decision="ALLOW", reasons=[]); '
        'json.dump(d, open(p, "w")); raise SystemExit(int(sys.argv[3]))', str(report), execution, str(code)]
    assert supervise(tmp_path, audit, command, 10) == 1
    assert audit.data['decision'] == 'BLOCK' and audit.data['execution'] == 'ERROR'
    assert audit.data['errors'][-1]['error_type'] == 'RuntimeError'


def test_janitor_keeps_latest_pointer_on_the_newer_run(tmp_path, monkeypatch):
    from security_harness import lifecycle
    monkeypatch.setattr(isolation, 'cleanup_run', lambda run: None)
    stale = AuditRun(tmp_path, 'security')
    lifecycle.prepare_run(tmp_path, stale.data['run_id'])
    newer = AuditRun(tmp_path, 'security')
    newer.finish()
    monkeypatch.setattr(lifecycle, 'owner_alive', lambda marker: False)
    assert sweep_stale(tmp_path) == [stale.data['run_id']]
    assert json.loads((stale.output / 'report.json').read_text())['execution'] == 'CANCELLED'
    assert (tmp_path / 'artifacts/latest.txt').read_text().strip() == newer.data['run_id']


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
    from security_harness.lifecycle import run_directory, valid_run_id
    assert not valid_run_id(run_id)
    with pytest.raises((ValueError, TypeError)):
        run_directory(Path("/tmp"), run_id)
    with pytest.raises((ValueError, TypeError)):
        cleanup_run(run_id)


def test_generated_run_identities_remain_valid():
    import secrets
    import uuid
    from security_harness.lifecycle import valid_run_id
    assert valid_run_id(str(uuid.uuid4())) and valid_run_id(secrets.token_hex(16))
