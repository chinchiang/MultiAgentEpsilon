"""父程序管理執行目錄、程序群組與取消後清理。

Parent-owned run directories, process groups and cleanup after cancellation."""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from .results import write_json

SOURCE_ROOT = Path(__file__).resolve().parents[1]


def group_alive(pid):
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == pid and fields[0] != 'Z':
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
    return False


def identity(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    return raw.rsplit(')', 1)[1].split()[19]


def run_directory(root, run_id):
    if not re.fullmatch(r'[a-f0-9-]{32,36}', run_id):
        raise ValueError('invalid run identity')
    return root / '.state' / 'runs' / run_id


def temporary_directory(run_id):
    if not re.fullmatch(r'[a-f0-9-]{32,36}', run_id):
        raise ValueError('invalid run identity')
    # PostgreSQL Unix socket 路徑須低於 Linux 的 108 位元組上限。 / Keep PostgreSQL Unix socket paths below Linux's 108-byte limit.
    return Path('/tmp') / f'epsilon-run-{os.getuid()}-{run_id}'


def prepare_run(root, run_id, operation='security'):
    work = run_directory(root, run_id)
    marker = {'run_id': run_id, 'operation': operation, 'pid': os.getpid(), 'start': identity(os.getpid()),
              'uid': os.getuid(), 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    work.mkdir(parents=True, mode=0o700)
    try:
        # 配置外部暫存資源前，先登記可復原的擁有者。 / A recoverable owner precedes external temporary resource allocation.
        write_json(work / 'owner.json', marker)
        temporary_directory(run_id).mkdir(mode=0o700)
    except Exception:
        shutil.rmtree(work)
        raise
    return work


def owner_alive(marker):
    if marker['boot'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
        return False
    try:
        raw = Path(f"/proc/{marker['pid']}/stat").read_text().rsplit(')', 1)[1].split()
        return raw[0] != 'Z' and raw[19] == marker['start']
    except FileNotFoundError:
        return False


def terminate_group(pid):
    if type(pid) is not int or pid <= 1 or pid == os.getpgrp():
        raise ValueError('invalid owned process group')
    # 即使直接 worker 已退出，也須終止其後代程序。 / Kill descendants even if the immediate worker has already exited.
    for signum, delay in ((signal.SIGTERM, 0.3), (signal.SIGKILL, 0)):
        try:
            os.killpg(pid, signum)
        except ProcessLookupError:
            break
        if delay:
            time.sleep(delay)
    deadline = time.monotonic() + 3
    while group_alive(pid):
        if time.monotonic() >= deadline:
            raise TimeoutError('process group cleanup incomplete')
        time.sleep(0.02)


def kill_group(process):
    terminate_group(process.pid)
    process.wait(timeout=5)


def cleanup(root, run_id):
    from .isolation import cleanup_run
    # CLI 終止後，daemon 仍可能正在完成請求。 / The daemon may still be finishing a request when its CLI is terminated.
    for _ in range(3):
        cleanup_run(run_id)
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


class SweepIncomplete(RuntimeError):
    """部分過期執行無法回收，其他項目仍繼續處理。

Some stale runs could not be reaped; the others were still processed."""

    def __init__(self, cleaned, failures):
        super().__init__('stale run cleanup incomplete')
        self.cleaned, self.failures = cleaned, failures


def sweep_stale(root):
    cleaned = []
    failures = []
    for work in sorted((root / '.state' / 'runs').glob('*')):
        try:
            if work.is_symlink():
                raise ValueError('invalid run directory')
            try:
                marker = json.loads((work / 'owner.json').read_text())
            except FileNotFoundError:
                # 另一 janitor 已移除，或初始化尚未發布擁有者標記； / Another janitor removed it, or initialization has not published
                # 該標記之前不會建立外部資源。 / ownership yet. No external resources exist before that marker.
                continue
            if marker['run_id'] != work.name or marker['uid'] != os.getuid():
                raise ValueError('invalid run owner')
            if not owner_alive(marker):
                if marker.get('operation') == 'model-smoke':
                    from .llm.lifecycle import recover
                    if recover(root, work.name):
                        cleaned.append(work.name)
                    continue
                same_boot = marker['boot'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                if same_boot and 'worker_pid' in marker:
                    try:
                        same_worker = identity(marker['worker_pid']) == marker['worker_start']
                    except FileNotFoundError:
                        same_worker = True  # 舊程序群組可能比其領導程序存活更久。 / An extant old process group can outlive its leader.
                    if same_worker:
                        terminate_group(marker['worker_pid'])
                cleanup(root, work.name)
                report = root / 'artifacts' / work.name / 'report.json'
                if report.exists():
                    from .audit import AuditRun
                    audit = AuditRun.__new__(AuditRun)
                    audit.output = report.parent
                    audit.data = json.loads(report.read_text())
                    audit.data.update(execution='CANCELLED', decision='BLOCK', reasons=['orphaned supervisor reaped'],
                                      cleanup={'completed': True, 'recovered_by_janitor': True,
                                               'run_directory_removed': not work.exists(),
                                               'temporary_directory_removed': not temporary_directory(work.name).exists(),
                                               'process_group_terminated': True, 'error_type': None,
                                               'boot_changed': not same_boot})
                    # 回收舊執行不可覆寫較新執行的索引。 / A reaped old run must not displace the index of a newer run.
                    audit.finish((('G1', 'scan'), ('G2', 'scan'), ('AUTH', 'test')), update_pointer=False)
                cleaned.append(work.name)
        except Exception as exc:
            # 繼續回收其他執行；每個失敗均回報，但不保存原文。 / Keep reaping the remaining runs; report every failure, without its text.
            failures.append({'run_id': work.name, 'error_type': type(exc).__name__})
    if failures:
        raise SweepIncomplete(cleaned, failures)
    return cleaned


def supervise(root, audit, command, max_seconds):
    work = prepare_run(root, audit.data['run_id'])
    cancelled = []
    handlers = {}
    process = None
    reason = None
    cleanup_error = None
    group_terminated = False
    deadline = time.monotonic() + max_seconds
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, lambda number, frame: cancelled.append(number))
        # supervisor 在登記前死亡時，閘門讀到 EOF 即退出。 / The gate exits on EOF if the supervisor dies before registration.
        gated = [sys.executable, '-I', str(SOURCE_ROOT / 'scripts/model_process.py'), *command]
        process = subprocess.Popen(gated, cwd=root, start_new_session=True, stdin=subprocess.PIPE,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env={**os.environ, 'TMPDIR': str(temporary_directory(audit.data['run_id']))})
        marker = json.loads((work / 'owner.json').read_text())
        marker.update(worker_pid=process.pid, worker_start=identity(process.pid))
        write_json(work / 'owner.json', marker)
        process.stdin.write(b'G')
        process.stdin.close()
        while process.poll() is None:
            if cancelled:
                reason = 'CANCELLED'
                break
            if time.monotonic() >= deadline:
                reason = 'TIMEOUT'
                break
            time.sleep(0.05)
    except Exception:
        reason = 'ERROR'
    finally:
        if process is not None:
            try:
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                kill_group(process)
                group_terminated = True
            except Exception as exc:
                cleanup_error = type(exc).__name__
        try:
            cleanup(root, audit.data['run_id'])
        except Exception as exc:
            cleanup_error = type(exc).__name__
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    # 讀取 worker 最後原子保存的進度，不使用父程序舊副本。 / Read the worker's last atomically persisted progress, not a stale parent copy.
    audit.data = json.loads((audit.output / 'report.json').read_text())
    finalized = False
    if (reason is None and not cancelled and cleanup_error is None and process is not None
            and process.returncode in (0, 1) and audit.data['execution'] == 'AWAITING_CLEANUP'):
        finalized = True
        pending = audit.data.pop('pending_decision')
        if process.returncode != (0 if pending == 'ALLOW' else 1):
            audit.fail(RuntimeError('worker exit/decision mismatch'))
        else:
            audit.data['decision'] = pending
            execution = audit.data.pop('pending_execution')
            audit.data['execution'] = 'COMPLETED' if execution == 'RUNNING' else execution
    audit.data['cleanup'] = {'completed': cleanup_error is None, 'error_type': cleanup_error,
                             'temporary_directory_removed': not temporary_directory(audit.data['run_id']).exists(),
                             'run_directory_removed': not work.exists(), 'process_group_terminated': group_terminated}
    if cancelled and reason is None:
        reason = 'CANCELLED'
    if reason:
        stage = audit.data['stage']
        if stage in ('G1', 'G2', 'AUTH') and not any(r['gate'] == stage for r in audit.data['records']):
            audit.add(stage, reason, 'test' if stage == 'AUTH' else 'scan', 0, 0, 'supervisor stopped run')
        audit.data.update(execution=reason, decision='BLOCK', reasons=['supervisor ' + reason.lower()])
    elif not finalized:
        # 只有完成清理交接後才能發布 worker 判定。 / Only the cleanup-gated handoff may publish a worker decision.
        audit.fail(RuntimeError('worker did not complete'))
    if cleanup_error:
        audit.data.update(execution='ERROR', decision='BLOCK', reasons=['cleanup incomplete'])
    audit.data['total_seconds'] = round(time.monotonic() - (deadline - max_seconds), 3)
    return audit.finish((('G1', 'scan'), ('G2', 'scan'), ('AUTH', 'test')))
