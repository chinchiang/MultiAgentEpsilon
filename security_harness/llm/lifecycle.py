"""使用共用執行清冊管理模型 supervisor 與復原，不使用 Docker。

Model supervisor and recovery using the shared run inventory, without Docker."""
import fcntl
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from ..lifecycle import (group_alive, identity, owner_alive, prepare_run, run_directory,
                         temporary_directory, terminate_group)
from ..results import write_json
from .gateway import ModelError
from .transport import strict_json

SOURCE_ROOT = Path(__file__).resolve().parents[2]
# 最多 16 筆審查乘以 16 KiB 原文，另加中繼資料。 / 16 reviews x 16 KiB bound raw responses, plus metadata.
REPORT_LIMIT = 1024 * 1024


def persist(path, data):
    write_json(path, data)
    # 放行子程序前，登記必須能承受擁有者崩潰。 / Registration must survive an owner crash before the child is released.
    with path.open('rb') as handle:
        os.fsync(handle.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def gated_command(command):
    return [sys.executable, '-I', str(SOURCE_ROOT / 'scripts/model_process.py'), *command]


def register_group(work, pid, role='child'):
    marker = json.loads((work / 'owner.json').read_text())
    if marker['uid'] != os.getuid() or marker['operation'] != 'model-smoke':
        raise ValueError('invalid model owner')
    if os.getsid(pid) != pid or os.getpgid(pid) != pid:
        raise ValueError('model child requires a dedicated session')
    persist(work / 'groups' / f'{pid}.json', {
        'pid': pid, 'start': identity(pid), 'boot': marker['boot'], 'uid': marker['uid'], 'role': role})


def read_report(root, run_id):
    path = root / 'artifacts' / run_id / 'report.json'
    try:
        if path.is_symlink() or path.stat().st_size > REPORT_LIMIT:
            raise ValueError('invalid evidence')
        with path.open('rb') as handle:
            raw = handle.read(REPORT_LIMIT + 1)
        if len(raw) > REPORT_LIMIT:
            raise ValueError('invalid evidence size')
        data = strict_json(raw)
        if (data.get('run_id') != run_id or data.get('operation') != 'model-smoke' or
                data.get('schema_version') != 2):
            raise ValueError('invalid evidence identity')
        for name in ('checks', 'calls'):
            if (not isinstance(data.get(name), list) or len(data[name]) > 16 or
                    any(not isinstance(item, dict) for item in data[name])):
                raise ValueError('invalid evidence records')
        return data
    except (OSError, ValueError, TypeError, AttributeError, ModelError):
        return {'schema_version': 2, 'run_id': run_id, 'operation': 'model-smoke',
                'advisory_only': True, 'status': 'INCOMPLETE', 'code': 'EVIDENCE_INVALID',
                'evidence_error': 'EVIDENCE_INVALID',
                'providers': [], 'checks': [], 'calls': []}


def stop_registered(work):
    current_boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    def stop(path):
        if path.is_symlink():
            raise ValueError('invalid process registration')
        group = json.loads(path.read_text())
        pid = group['pid']
        if type(pid) is not int or pid <= 1 or group['uid'] != os.getuid() or path.name != f'{pid}.json':
            raise ValueError('invalid process identity')
        if group['boot'] != current_boot:
            return  # host 重開機後不可對新開機的程序傳送訊號。 / Host reboot: never signal a new boot's processes.
        try:
            if identity(pid) != group['start']:
                return  # PID 重用時不可對新群組傳送訊號。 / PID reuse: do not signal the new process group.
        except FileNotFoundError:
            pass  # 已登記群組可能比原領導程序存活更久。 / A registered group can outlive its original leader.
        terminate_group(pid)
        deadline = time.monotonic() + 3
        while True:
            if not group_alive(pid):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('model process cleanup incomplete')
            time.sleep(0.02)
    # 先停止產生者再重新列舉；接收 SIGTERM 時仍可能 / Freeze the producer first, then enumerate again: it could register another
    # 登記新子程序，尚未登記的閘門子程序則讀到 EOF。 / child while receiving SIGTERM. A pre-registration gated child sees EOF.
    for path in sorted((work / 'groups').glob('*.json')):
        if path.is_symlink():
            raise ValueError('invalid process registration')
        if json.loads(path.read_text()).get('role') == 'worker':
            stop(path)
    for path in sorted((work / 'groups').glob('*.json')):
        stop(path)


@contextmanager
def cleanup_lock(work):
    # 非阻塞 flock 序列化同時執行的 janitor，不重新建立執行目錄。 / Nonblocking flock serializes concurrent janitors. Never recreate a run.
    try:
        fd = os.open(work / 'cleanup.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except FileNotFoundError:
        yield False
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:
        os.close(fd)


def complete_worker_report(data, providers, returncode):
    # 不可因空集合、過期報告或缺少供應商嘗試而成功。 / No vacuous success, stale report or success from missing provider attempts.
    checks, calls = data.get('checks', []), data.get('calls', [])
    return (returncode == 0 and data.get('status') == 'AWAITING_CLEANUP' and
            data.get('pending_status') == 'COMPLETE' and bool(providers) and
            data.get('providers') == providers and
            [c.get('provider') for c in checks] == providers and
            all(c.get('status') == 'SUCCESS' for c in checks) and
            [c.get('provider') for c in calls] == providers and
            all(c.get('status') == 'SUCCESS' for c in calls))


def finish(root, run_id, *, providers=(), returncode=None, reason=None, recovered=False, cancelled=None, expected_report=None):
    work = run_directory(root, run_id)
    report = root / 'artifacts' / run_id / 'report.json'
    cleanup_error = None
    try:
        stop_registered(work)
    except Exception as exc:
        cleanup_error = type(exc).__name__
    # 群組停止後，worker 才無法繼續覆寫證據。 / Workers can no longer overwrite evidence after their groups are stopped.
    data = read_report(root, run_id)
    try:
        completed = cleanup_error is None and reason is None and complete_worker_report(data, providers, returncode)
    except (TypeError, AttributeError):
        completed = False
    previous_status = data.get('status')
    data.pop('pending_status', None)
    data.update(status='INCOMPLETE', cleanup={'completed': False, 'recovered_by_janitor': recovered})
    if reason:
        data['code'] = reason
    for check in data.get('checks', []):
        if check.get('status') == 'RUNNING':
            check.update(status='CANCELLED' if reason == 'CANCELLED' else 'ERROR', code=reason or 'WORKER_FAILED')
    if data.get('task') == 'blind-review' or (expected_report or {}).get('task') == 'blind-review':
        try:
            from .benchmark_score import summarize
            data['analysis'] = summarize(data, (expected_report or {}).get('plan'))
        except Exception:
            completed = False
            data.update(analysis=None, code='EVALUATION_INVALID')
    elif expected_report is not None:
        # Smoke worker 也綁定 supervisor 不可變計畫與限額。 / Smoke workers are bound to the supervisor's immutable plan and limits too.
        immutable = ('providers', 'fixture', 'implementation_sha256', 'model_roe_sha256',
                     'limits', 'total_timeout_seconds', 'max_output_tokens_per_call')
        calls = data.get('calls', [])
        reservations_valid = (type(data.get('reserved_calls')) is int and
            type(data.get('reserved_output_tokens')) is int and
            all(type(c.get('reserved')) is bool and c.get('reserved') is True and
                type(c.get('reserved_output_tokens')) is int and
                c['reserved_output_tokens'] == expected_report['max_output_tokens_per_call'] for c in calls) and
            data['reserved_calls'] == len(calls) and
            data['reserved_output_tokens'] == len(calls) * expected_report['max_output_tokens_per_call'])
        if not all(data.get(k) == expected_report.get(k) for k in immutable) or not reservations_valid:
            completed = False
            data['code'] = 'EVALUATION_INVALID'
    try:
        if cleanup_error:
            raise RuntimeError('process cleanup failed')
        temp = temporary_directory(run_id)
        if work.is_symlink() or temp.is_symlink():
            raise ValueError('invalid model run directory')
        if temp.exists():
            shutil.rmtree(temp)
        # 移除復原清冊前，先保存阻擋狀態的檢查點。 / Persist a blocking checkpoint before removing the recovery inventory.
        persist(report, data)
        shutil.rmtree(work)
    except Exception as exc:
        cleanup_error = cleanup_error or type(exc).__name__
    data['cleanup'].update(completed=cleanup_error is None, error_type=cleanup_error,
                           process_groups_terminated=cleanup_error is None,
                           temporary_directory_removed=not temporary_directory(run_id).exists(),
                           run_directory_removed=not work.exists())
    if cancelled:
        reason = 'CANCELLED'
    if cleanup_error:
        data.update(status='ERROR', code='CLEANUP_FAILED')
    elif reason in ('CANCELLED', 'TIMEOUT'):
        data.update(status=reason, code=reason)
    elif completed:
        data.update(status='COMPLETE', code=None)
    else:
        data.update(status='INCOMPLETE', code=data.get('code') or
                    ('WORKER_FAILED' if previous_status != 'AWAITING_CLEANUP' else 'PROVIDER_INCOMPLETE'))
    persist(report, data)
    return data


def recover(root, run_id):
    work = run_directory(root, run_id)
    with cleanup_lock(work) as locked:
        if not locked:
            return False
        marker = json.loads((work / 'owner.json').read_text())
        if marker['run_id'] != run_id or marker['uid'] != os.getuid() or marker['operation'] != 'model-smoke':
            raise ValueError('invalid model owner')
        if owner_alive(marker):
            return False
        data = finish(root, run_id, reason='CANCELLED', recovered=True)
        if not data['cleanup']['completed']:
            raise RuntimeError('model cleanup incomplete')
        return True


def supervise(root, report, command, max_seconds):
    if (type(max_seconds) not in (int, float) or not math.isfinite(max_seconds)
            or not 0 < max_seconds <= 130):
        raise ValueError('invalid model supervisor deadline')
    run_id = report['run_id']
    work = prepare_run(root, run_id, operation='model-smoke')
    persist(work / 'owner.json', json.loads((work / 'owner.json').read_text()))
    cancelled, handlers = [], {}
    process, reason = None, None
    deadline = time.monotonic() + max_seconds
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.signal(sig, lambda number, frame: cancelled.append(number))
        process = subprocess.Popen(gated_command(command), cwd=root, start_new_session=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env={**os.environ, 'TMPDIR': str(temporary_directory(run_id))})
        register_group(work, process.pid, role='worker')
        process.stdin.write(b'G')
        process.stdin.close()
        while process.poll() is None:
            if cancelled:
                reason = 'CANCELLED'
                break
            if time.monotonic() >= deadline:
                reason = 'TIMEOUT'
                break
            time.sleep(0.02)
    except Exception:
        reason = 'SUPERVISOR_FAILED'
    finally:
        # 尚未登記的閘門子程序仍由此 Popen handle 擁有。 / Even an unregistered gated child is owned by this Popen handle.
        if process is not None:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            if process.returncode is None:
                terminate_group(process.pid)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # 群組終止後仍存活的 worker 不可略過後續收尾。 / A worker that outlives its group kill must not skip finalization below.
                reason = reason or 'SUPERVISOR_FAILED'
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        try:
            with cleanup_lock(work) as locked:
                if not locked:
                    raise RuntimeError('model cleanup lock unavailable')
                data = finish(root, run_id, providers=report['providers'],
                              returncode=process.returncode if process else None,
                              reason='CANCELLED' if cancelled else reason, cancelled=cancelled, expected_report=report)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    return data
