"""每個子程序都只收到同一份基本環境加上自己角色的名稱，在真正的啟動路徑上觀察。

Every child process receives the one base environment plus its own role's names, observed on the real launch path."""
import asyncio
import json
import shutil
import sys
import uuid

import pytest

# 基本程序、語系、代理與 CA 變數；值為合成值。 / Basic process, locale, proxy and CA variables, with synthetic values.
BASE = {"PATH": "/usr/bin:/bin", "HOME": "/home/synthetic", "USER": "synthetic", "LOGNAME": "synthetic",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "LC_CTYPE": "C.UTF-8", "TZ": "UTC",
        "HTTP_PROXY": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128",
        "NO_PROXY": "localhost", "ALL_PROXY": "socks5://proxy.invalid:1080",
        "http_proxy": "http://proxy.invalid:3128", "https_proxy": "http://proxy.invalid:3128",
        "no_proxy": "localhost", "all_proxy": "socks5://proxy.invalid:1080",
        "SSL_CERT_FILE": "/etc/ssl/synthetic.pem", "SSL_CERT_DIR": "/etc/ssl/certs",
        "REQUESTS_CA_BUNDLE": "/etc/ssl/synthetic-bundle.pem"}
# 權杖、金鑰、libpq 設定、角色以外的 AWS 名稱，以及大小寫混用的代理名稱都不可傳下去。 / Tokens, keys, libpq settings,
# AWS names outside a role, and mixed-case proxy names never pass.
DROPPED = {"GH_TOKEN": "synthetic-github-token", "GITHUB_TOKEN": "synthetic-actions-token",
           "GEMINI_API_KEY": "synthetic-gemini-key", "PGPASSWORD": "synthetic-pg-password",
           "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/synthetic", "Http_Proxy": "http://attacker.invalid:3128"}
DUMP = [sys.executable, '-c',
        'import json,os; from pathlib import Path; Path("child-env.json").write_text(json.dumps(dict(os.environ)))']


def no_containers(run_id):
    """這些 worker 不建立容器，容器清理換成什麼都不做。 / These workers create no containers, so container cleanup
    does nothing."""


def security_worker(tmp_path, monkeypatch, request):
    from security_harness.audit import AuditRun
    from security_harness.lifecycle import supervise
    supervise(tmp_path, AuditRun(tmp_path, 'security'), DUMP, 10, no_containers)
    return json.loads((tmp_path / 'child-env.json').read_text())


def model_worker(tmp_path, monkeypatch, request):
    from scripts.model_smoke import initial_report
    from security_harness.llm import lifecycle as life
    report = initial_report(['mock'], str(uuid.uuid4()))
    life.persist(tmp_path / 'artifacts' / report['run_id'] / 'report.json', report)
    life.supervise(tmp_path, report, DUMP, 10)
    return json.loads((tmp_path / 'child-env.json').read_text())


def aws_cli(tmp_path, monkeypatch, request):
    from security_harness.supervision import prepare_run, run_directory, temporary_directory
    from tests.test_model_gateway import cli_fixture
    run_id = str(uuid.uuid4())
    prepare_run(tmp_path, run_id, operation='model-smoke')
    try:
        cli = cli_fixture(tmp_path, "import json, os\nprint(json.dumps(dict(os.environ)))\n")
        cli.run_directory = run_directory(tmp_path, run_id)
        return asyncio.run(cli.converse('ap-southeast-1', {'modelId': 'synthetic'}))
    finally:
        shutil.rmtree(temporary_directory(run_id), ignore_errors=True)


def attestation_verifier(tmp_path, monkeypatch, request):
    # 證明驗證器只在子程序邊界替換；在同一邊界記錄它收到的環境。 / The attestation verifier is substituted only at the
    # subprocess boundary; record the environment it receives at that same boundary.
    from security_harness import processes
    from security_harness import trusted_publisher as publisher
    from tests.test_trusted_publisher import publishable_repository
    bundle = request.getfixturevalue('bundle')
    github, _ = publishable_repository(bundle, tmp_path, monkeypatch)
    answer, seen = processes.bounded_output, {}
    def record(*args, **kwargs):
        seen.update(kwargs['env'])
        return answer(*args, **kwargs)
    monkeypatch.setattr(processes, 'bounded_output', record)
    publisher.collect(github, bundle['settings'], 5, 100, bundle['gate_policy'])
    return seen


@pytest.mark.parametrize('child,role', [
    (security_worker, {"DOCKER_CONFIG": "/home/synthetic/.docker"}),
    (model_worker, {}),
    (aws_cli, {"AWS_PROFILE": "synthetic-profile", "AWS_MAX_ATTEMPTS": "1"}),
    (attestation_verifier, {"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}),
], ids=['security-worker', 'model-worker', 'aws-cli', 'attestation-verifier'])
def test_every_child_receives_the_base_environment_and_its_role_names_only(tmp_path, monkeypatch, request,
                                                                           child, role):
    for name, value in {**BASE, **DROPPED, "DOCKER_CONFIG": "/home/synthetic/.docker",
                        "AWS_PROFILE": "synthetic-profile"}.items():
        monkeypatch.setenv(name, value)
    seen = child(tmp_path, monkeypatch, request)
    assert {k: seen.get(k) for k in BASE} == BASE
    assert {k: seen.get(k) for k in role} == role
    assert not set(DROPPED) & set(seen)


class FakeRole:
    """假角色：證據放在記憶體，外部清理可設定為失敗或在收尾期間收到訊號。

A fake role: evidence stays in memory, and its external cleanup can fail or receive a signal during finalization.
    """
    operation, ceiling = 'fake-role', 10

    def __init__(self, release=None, checkpoint_error=None):
        self.released, self.reads, self.closed = [], 0, []
        self.on_release, self.checkpoint_error = release, checkpoint_error

    def release(self, run_id):
        self.released.append(run_id)
        if self.on_release:
            self.on_release(run_id)

    def read(self):
        self.reads += 1
        return {'worker': 'evidence'}

    def close(self, evidence, outcome):
        assert evidence == {'worker': 'evidence'}
        self.closed.append(outcome)
        if self.checkpoint_error and len(self.closed) == 1:
            raise self.checkpoint_error
        return outcome


def supervised(tmp_path, role, command, max_seconds=10, env=None):
    from security_harness import supervision
    run_id = str(uuid.uuid4())
    result = supervision.supervise(tmp_path, run_id, role, command, {'PATH': '/usr/bin:/bin'} if env is None else env,
                                   max_seconds)
    return run_id, result


def inventory_removed(root, run_id):
    from security_harness.supervision import temporary_directory
    return not (root / '.state/runs' / run_id).exists() and not temporary_directory(run_id).exists()


def signal_supervisor(run_id):
    import os
    import signal
    os.kill(os.getpid(), signal.SIGTERM)


def raise_runtime_error(run_id):
    raise RuntimeError('sensitive docker diagnostics')


def replace_run_directory_with_symlink(root):
    # 執行清冊被換成指向別處的 symlink；刪除時不可跟著它刪到別處。 / The run inventory is swapped for a symlink to
    # elsewhere; removal must never follow it.
    def release(run_id):
        work = root / '.state/runs' / run_id
        work.rename(root / 'moved-run')
        work.symlink_to(root / 'moved-run')
    return release


def replace_temporary_with_symlink(run_id):
    from security_harness.supervision import temporary_directory
    temporary = temporary_directory(run_id)
    shutil.rmtree(temporary)
    temporary.symlink_to('/tmp')


EXIT = [sys.executable, '-c', 'raise SystemExit({})']
SLEEP = [sys.executable, '-c', 'import time; time.sleep(30)']
# worker 對 supervisor 送 SIGTERM 後持續執行，直到被停止。 / The worker sends SIGTERM to its supervisor, then keeps
# running until it is stopped.
CANCEL = [sys.executable, '-c', 'import os,signal,time; os.kill(os.getppid(), signal.SIGTERM); time.sleep(30)']


@pytest.mark.parametrize('command,max_seconds,release,expected', [
    ([EXIT[0], EXIT[1], EXIT[2].format(0)], 10, None, ('EXITED', None, 0)),
    ([EXIT[0], EXIT[1], EXIT[2].format(1)], 10, None, ('EXITED', None, 1)),
    ([EXIT[0], EXIT[1], EXIT[2].format(2)], 10, None, ('EXITED', None, 2)),
    (SLEEP, 0.5, None, ('TIMEOUT', 'TIMEOUT', -15)),
    (CANCEL, 10, None, ('CANCELLED', 'CANCELLED', -15)),
    # 已有的停止原因不被收尾期間的訊號改寫。 / A signal during finalization never rewrites an existing stop reason.
    (SLEEP, 0.5, signal_supervisor, ('TIMEOUT', 'TIMEOUT', -15)),
    # worker 自行結束後才收到訊號，成功也不可發布。 / A signal after the worker exited on its own still keeps success
    # unpublished.
    ([EXIT[0], EXIT[1], EXIT[2].format(0)], 10, signal_supervisor, ('CANCELLED', 'CANCELLED', 0)),
], ids=['exit-0', 'exit-1', 'exit-2', 'timeout', 'cancelled', 'timeout-then-signal', 'exit-then-signal'])
def test_supervision_outcome_follows_the_first_stop_reason(tmp_path, command, max_seconds, release, expected):
    role = FakeRole(release)
    run_id, final = supervised(tmp_path, role, command, max_seconds)
    assert (final.kind, final.stop, final.returncode) == expected
    assert final.cleanup == {'completed': True, 'error_type': None, 'temporary_directory_removed': True,
                             'run_directory_removed': True, 'process_group_terminated': True,
                             'recovered_by_janitor': False}
    assert role.released == [run_id] and role.reads == 1
    assert inventory_removed(tmp_path, run_id)


def test_every_close_starts_with_a_blocking_checkpoint_written_before_the_inventory_is_removed(tmp_path):
    from security_harness.supervision import temporary_directory
    seen = []
    class Observing(FakeRole):
        def close(self, evidence, outcome):
            seen.append((tmp_path / '.state/runs').exists() and any((tmp_path / '.state/runs').iterdir()))
            return super().close(evidence, outcome)
    role = Observing()
    run_id, final = supervised(tmp_path, role, [EXIT[0], EXIT[1], EXIT[2].format(0)])
    checkpoint, last = role.closed
    assert checkpoint.kind == 'CLEANUP_FAILED' and not checkpoint.cleanup['completed']
    assert not checkpoint.cleanup['run_directory_removed'] and last is final and final.kind == 'EXITED'
    assert seen == [True, False]
    assert not temporary_directory(run_id).exists()


def test_supervisor_failure_is_a_fixed_outcome_without_its_text(tmp_path):
    # 非字串的環境值使啟動失敗，不需要 patch。 / A non-string environment value fails the launch without any patch.
    role = FakeRole()
    run_id, final = supervised(tmp_path, role, [EXIT[0], EXIT[1], EXIT[2].format(0)], env={'PATH': 1})
    assert (final.kind, final.stop, final.error_type, final.returncode) == ('SUPERVISOR_FAILED', 'SUPERVISOR_FAILED',
                                                                             'TypeError', None)
    assert inventory_removed(tmp_path, run_id)


@pytest.mark.parametrize('make_role,error_type', [
    (lambda root: FakeRole(raise_runtime_error), 'RuntimeError'),
    (lambda root: FakeRole(replace_temporary_with_symlink), 'ValueError'),
    (lambda root: FakeRole(replace_run_directory_with_symlink(root)), 'ValueError'),
    (lambda root: FakeRole(checkpoint_error=OSError('sensitive disk diagnostics')), 'OSError'),
], ids=['external-cleanup', 'symlinked-temporary-directory', 'symlinked-run-directory', 'checkpoint'])
def test_failed_cleanup_step_keeps_the_run_inventory_for_the_janitor(tmp_path, make_role, error_type):
    from security_harness.supervision import temporary_directory
    role = make_role(tmp_path)
    try:
        run_id, final = supervised(tmp_path, role, [EXIT[0], EXIT[1], EXIT[2].format(0)])
        assert final.kind == 'CLEANUP_FAILED' and final.cleanup['error_type'] == error_type
        assert len(role.closed) == 2 and role.closed[-1] is final
        assert (tmp_path / '.state/runs' / run_id / 'owner.json').exists()
        assert 'sensitive' not in json.dumps(final.cleanup)
    finally:
        for path in (tmp_path / '.state/runs').glob('*'):
            temporary = temporary_directory(path.name)
            if temporary.is_symlink():
                temporary.unlink()
            shutil.rmtree(temporary, ignore_errors=True)


def test_finalization_without_the_cleanup_lock_touches_neither_evidence_nor_inventory(tmp_path):
    from security_harness.supervision import CleanupLockUnavailable, cleanup_lock, prepare_run, temporary_directory
    from tests.model_support import finalize
    run_id = str(uuid.uuid4())
    work = prepare_run(tmp_path, run_id, 'fake-role')
    role = FakeRole()
    try:
        with cleanup_lock(work) as locked:
            assert locked
            with pytest.raises(CleanupLockUnavailable):
                finalize(tmp_path, run_id, role, returncode=0)
        assert (role.released, role.reads, role.closed) == ([], 0, [])
        assert work.exists() and temporary_directory(run_id).exists()
    finally:
        shutil.rmtree(temporary_directory(run_id), ignore_errors=True)


@pytest.mark.parametrize('rebooted', [False, True])
def test_janitor_recovery_goes_through_the_same_protocol_as_cancelled(tmp_path, rebooted):
    from security_harness.supervision import persist, prepare_run, recover, sweep_runs
    run_id = str(uuid.uuid4())
    work = prepare_run(tmp_path, run_id, 'fake-role')
    marker = json.loads((work / 'owner.json').read_text())
    # 擁有者已死亡：另一次開機，或 PID 不再是同一個程序。 / The owner died: another boot, or the PID is no longer the
    # same process.
    marker.update(boot='previous-boot') if rebooted else marker.update(start='not-the-owner')
    persist(work / 'owner.json', marker)
    role = FakeRole()
    cleaned, failures = sweep_runs(tmp_path, {'fake-role': lambda root, run, owner: recover(root, run, owner, role)})
    assert (cleaned, failures) == ([run_id], [])
    checkpoint, final = role.closed
    assert (final.kind, final.stop, final.returncode) == ('CANCELLED', 'CANCELLED', None)
    assert final.cleanup['recovered_by_janitor'] and final.cleanup['boot_changed'] is rebooted
    assert role.released == [run_id] and inventory_removed(tmp_path, run_id)


def test_janitor_recovery_that_cannot_clean_up_is_reported_and_retried(tmp_path):
    from security_harness.supervision import persist, prepare_run, recover, sweep_runs
    run_id = str(uuid.uuid4())
    work = prepare_run(tmp_path, run_id, 'fake-role')
    marker = json.loads((work / 'owner.json').read_text())
    persist(work / 'owner.json', {**marker, 'boot': 'previous-boot'})
    failing = FakeRole(raise_runtime_error)
    assert sweep_runs(tmp_path, {'fake-role': lambda root, run, owner: recover(root, run, owner, failing)}) == (
        [], [{'run_id': run_id, 'error_type': 'RuntimeError'}])
    assert failing.closed[-1].kind == 'CLEANUP_FAILED' and work.exists()
    healthy = FakeRole()
    assert sweep_runs(tmp_path, {'fake-role': lambda root, run, owner: recover(root, run, owner, healthy)}) == (
        [run_id], [])
    assert inventory_removed(tmp_path, run_id)
