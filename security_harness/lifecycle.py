"""security 角色的受監督執行：計畫、worker 環境、容器與執行狀態清理、收尾，以及擁有者死亡後的復原。

The security role of a supervised run: its plan, worker environment, container and run-state cleanup, finalization,
and recovery after its owner died."""
import json
import os
import shutil
import time
from datetime import datetime, timedelta, timezone
from .results import required_gate_kinds
from .supervision import (PlanMismatch, child_environment, current_boot, plan_changed, plan_digest, run_directory,
                          stop_registered, supervised_run, temporary_directory)

# 遠大於 RoE 的 120 秒執行上限。 / Well beyond the RoE's 120-second run limit.
ORPHAN_CONTAINER_AGE = timedelta(minutes=10)
# RoE 允許的最長整體期限。 / The longest total deadline the RoE allows.
MAX_TOTAL_SECONDS = 600


def remove_run_containers(run_id):
    from .isolation import cleanup_run
    cleanup_run(run_id)


def cleanup(root, run_id, remove_containers=remove_run_containers):
    # CLI 終止後，daemon 仍可能正在完成請求。 / The daemon may still be finishing a request when its CLI is terminated.
    for _ in range(3):
        remove_containers(run_id)
        time.sleep(0.1)
    work = run_directory(root, run_id)
    if work.exists():
        if work.is_symlink():
            raise ValueError('run directory must not be a symlink')
        marker = json.loads((work / 'owner.json').read_text())
        if marker['run_id'] != run_id or marker['uid'] != os.getuid():
            raise ValueError('run ownership mismatch')
        temporary = temporary_directory(run_id)
        if temporary.is_symlink():
            raise ValueError('temporary directory must not be a symlink')
        if temporary.exists():
            shutil.rmtree(temporary)
        shutil.rmtree(work)


def remove_orphan_containers(root):
    from . import isolation
    # daemon 較慢時，容器可能在 cleanup 之後才建立。 / A slow daemon can create a container after its run's cleanup.
    ids = isolation.docker('ps', '-aq', '--filter', 'label=epsilon.isolated=true', timeout=30).stdout.split()
    if not ids:
        return
    # 較新的容器可能屬於同主機另一個 checkout 仍在進行的執行。 / A younger container may belong to another checkout's live run.
    cutoff = datetime.now(timezone.utc) - ORPHAN_CONTAINER_AGE
    # 回收後仍留下目錄的執行，其擁有者仍存活。 / Runs whose directory survived the reaping still have a live owner.
    live = {work.name for work in (root / '.state' / 'runs').glob('*')}
    old = [c['Id'] for c in json.loads(isolation.docker('inspect', *ids, timeout=30).stdout)
           if datetime.fromisoformat(c['Created']) < cutoff
           and (c['Config']['Labels'] or {}).get('epsilon.run') not in live]
    if old:
        isolation.docker('rm', '--force', *old, timeout=30)


def recover(root, run_id, marker):
    """回收擁有者已死亡的 security 執行：停止登記的群組、清除容器與執行狀態，並以 CANCELLED 收尾證據。

Reap a security run whose owner died: stop its registered groups, remove its containers
    and run state, and close its evidence as CANCELLED.
    """
    work = run_directory(root, run_id)
    same_boot = marker['boot'] == current_boot()
    stop_registered(work)
    cleanup(root, run_id)
    report = root / 'artifacts' / run_id / 'report.json'
    if report.exists():
        from .audit import AuditRun
        audit = AuditRun.__new__(AuditRun)
        audit.output = report.parent
        audit.data = json.loads(report.read_text())
        audit.data.update(execution='CANCELLED', decision='BLOCK', reasons=['orphaned supervisor reaped'],
                          cleanup={'completed': True, 'recovered_by_janitor': True,
                                   'run_directory_removed': not work.exists(),
                                   'temporary_directory_removed': not temporary_directory(run_id).exists(),
                                   'process_group_terminated': True, 'error_type': None,
                                   'boot_changed': not same_boot})
        # 回收舊執行不可覆寫較新執行的索引。 / A reaped old run must not displace the index of a newer run.
        audit.finish(required_gate_kinds(root), update_pointer=False)
    return True


# supervisor 在放行 worker 前決定的計畫欄位；worker 報告中的這些欄位必須與 supervisor 持有的值相同。
# / The plan fields the supervisor decides before releasing the worker; the worker's report must keep the values
# the supervisor holds.
SECURITY_IMMUTABLE = ('run_id', 'operation', 'created_at', 'variant', 'candidate', 'resource_limits',
                      'policy_digest', 'roe_sha256', 'evaluator_digest')


def matches_plan(report, digest):
    """worker 讀回的報告是否仍是命令列摘要所指的計畫。 / Whether the report the worker read back is still the plan
    its command-line digest names."""
    return plan_digest(report, SECURITY_IMMUTABLE) == digest


# security worker 另需 docker 設定；不需權杖、供應商金鑰或 libpq 設定。 / The security worker also needs the docker
# configuration; it needs no token, provider key or libpq setting.
SECURITY_WORKER_EXTRA = frozenset({"DOCKER_CONFIG"})


def security_worker_environment(environ=os.environ):
    """security worker 的環境：基本環境加上 docker 設定。

The security worker's environment: the base environment plus the docker configuration.
    """
    return child_environment(environ, SECURITY_WORKER_EXTRA)


def supervise(root, audit, command, max_seconds, remove_containers=remove_run_containers):
    run_id = audit.data['run_id']
    planned = {key: audit.data.get(key) for key in SECURITY_IMMUTABLE}
    with supervised_run(root, run_id, 'security', max_seconds, MAX_TOTAL_SECONDS) as run:
        run.run(command, security_worker_environment(os.environ))
        cleanup_error = run.stop_error
        try:
            cleanup(root, run_id, remove_containers)
        except Exception as exc:
            cleanup_error = type(exc).__name__
    reason, cancelled, returncode = run.reason, run.cancelled, run.returncode
    # 讀取 worker 最後原子保存的進度，不使用父程序舊副本。 / Read the worker's last atomically persisted progress, not a stale parent copy.
    audit.data = json.loads((audit.output / 'report.json').read_text())
    # 發布的證據只能帶 supervisor 實際使用的計畫，不採用 worker 改過的值。 / Published evidence carries only the plan
    # the supervisor actually used, never values the worker changed.
    changed = plan_changed(audit.data, planned)
    audit.data.update(planned)
    finalized = False
    if (not changed and reason is None and not cancelled and cleanup_error is None and returncode in (0, 1)
            and audit.data['execution'] == 'AWAITING_CLEANUP'):
        finalized = True
        pending = audit.data.pop('pending_decision')
        if returncode != (0 if pending == 'ALLOW' else 1):
            audit.fail(RuntimeError('worker exit/decision mismatch'))
        else:
            audit.data['decision'] = pending
            execution = audit.data.pop('pending_execution')
            audit.data['execution'] = 'COMPLETED' if execution == 'RUNNING' else execution
    audit.data['cleanup'] = {'completed': cleanup_error is None, 'error_type': cleanup_error,
                             'temporary_directory_removed': not temporary_directory(run_id).exists(),
                             'run_directory_removed': not run.work.exists(),
                             'process_group_terminated': run.stop_error is None}
    if cancelled and reason is None:
        reason = 'CANCELLED'
    if run.error_type:
        # 保留監督程序例外型別，不保存例外文字。 / Keep the supervisor's exception type, never its text.
        audit.data['errors'].append({'stage': 'supervisor', 'error_type': run.error_type})
    if reason:
        stage = audit.data['stage']
        kinds = dict(required_gate_kinds(root))
        if stage in kinds and not any(r['gate'] == stage for r in audit.data['records']):
            audit.add(stage, reason, kinds[stage], 0, 0, 'supervisor stopped run')
        audit.data.update(execution=reason, decision='BLOCK', reasons=['supervisor ' + reason.lower()])
    elif changed or returncode == 2:
        # exit 2 表示 worker 讀回的計畫與命令列摘要不符。 / Exit 2 means the plan the worker read back did not match
        # the digest on its command line.
        audit.fail(PlanMismatch('worker report differs from the plan'))
    elif not finalized:
        # 只有完成清理交接後才能發布 worker 判定。 / Only the cleanup-gated handoff may publish a worker decision.
        audit.fail(RuntimeError('worker did not complete'))
    if cleanup_error:
        audit.data.update(execution='ERROR', decision='BLOCK', reasons=['cleanup incomplete'])
    audit.data['total_seconds'] = run.seconds
    return audit.finish(required_gate_kinds(root))
