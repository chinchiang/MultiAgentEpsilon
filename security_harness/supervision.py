"""受監督執行：supervisor 啟動 worker、在放行前持久登記、等待結束、期限或訊號，再停止所有登記的程序群組並收尾。
收尾協定在這裡：持有清理鎖、訊號處理器仍有效時，清除角色的外部資源，先寫阻擋檢查點再刪執行清冊，最後以監督結果寫入
最終證據；擁有者死亡的執行由 janitor 經同一協定回收。每個子程序都從同一份基本環境出發，各角色只加上自己需要的名稱；
證據格式留在各角色。

Supervised runs: the supervisor starts a worker, registers it durably before releasing it, waits for its exit, the
deadline or a signal, then stops every registered process group and finalizes the run. The finalization protocol lives
here: under the cleanup lock and with the signal handlers still installed, it releases the role's external resources,
writes a blocking checkpoint before removing the run inventory, and writes the final evidence from the supervision
outcome; a janitor reaps a dead owner's run through the same protocol. Every child starts from one base environment
and each role adds only the names it needs; the evidence format stays with each role."""
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

from .results import write_json

SOURCE_ROOT = Path(__file__).resolve().parents[1]

# 找到程式、語系、代理與 CA 所需的名稱；不含任何權杖、金鑰或改變連線目的地的設定。 / The names needed to find
# programs, locale, proxies and CAs; no token, key or setting that changes where a child connects.
BASE_ENV = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"})


def child_environment(environ, extra=()):
    """基本環境加上角色的額外名稱；名稱須完全相符，大小寫不同即丟棄。

The base environment plus the role's extra names. Names must match exactly; any
    other casing is dropped.
    """
    return {k: v for k, v in environ.items() if k in BASE_ENV or k in extra}


def group_alive(pid):
    """程序群組是否仍有非殭屍成員。 / Whether a process group still has a non-zombie member."""
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == pid and fields[0] != 'Z':
                return True
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError, ValueError):
            # 程序在列舉時消失，或 /proc 受 hidepid 限制。 / The process vanished mid-scan, or /proc is restricted.
            continue
    return False


def identity(pid):
    raw = Path(f'/proc/{pid}/stat').read_text()
    return raw.rsplit(')', 1)[1].split()[19]


def current_boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


# 32 位十六進位或標準 UUID；與發布器使用的格式一致。 / 32 hex digits or a canonical UUID, as the publisher expects.
RUN_ID = re.compile(r'[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


def valid_run_id(run_id):
    return type(run_id) is str and RUN_ID.fullmatch(run_id) is not None


def run_directory(root, run_id):
    if not valid_run_id(run_id):
        raise ValueError('invalid run identity')
    return root / '.state' / 'runs' / run_id


def temporary_directory(run_id):
    if not valid_run_id(run_id):
        raise ValueError('invalid run identity')
    # PostgreSQL Unix socket 路徑須低於 Linux 的 108 位元組上限。 / Keep PostgreSQL Unix socket paths below Linux's 108-byte limit.
    return Path('/tmp') / f'epsilon-run-{os.getuid()}-{run_id}'


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


def prepare_run(root, run_id, operation):
    work = run_directory(root, run_id)
    marker = {'run_id': run_id, 'operation': operation, 'pid': os.getpid(), 'start': identity(os.getpid()),
              'uid': os.getuid(), 'boot': current_boot()}
    work.mkdir(parents=True, mode=0o700)
    try:
        # 配置外部暫存資源前，先登記可復原的擁有者。 / A recoverable owner precedes external temporary resource allocation.
        persist(work / 'owner.json', marker)
        temporary_directory(run_id).mkdir(mode=0o700)
    except Exception:
        shutil.rmtree(work)
        raise
    return work


def owner_alive(marker):
    if marker['boot'] != current_boot():
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


def gated_command(command):
    # 擁有者在登記前死亡時，閘門讀到 EOF 即退出。 / The gate exits on EOF if the owner dies before registration.
    return [sys.executable, '-I', str(SOURCE_ROOT / 'scripts/model_process.py'), *command]


def register_group(work, pid, role='child'):
    marker = json.loads((work / 'owner.json').read_text())
    if marker['uid'] != os.getuid():
        raise ValueError('invalid run owner')
    if os.getsid(pid) != pid or os.getpgid(pid) != pid:
        raise ValueError('supervised child requires a dedicated session')
    persist(work / 'groups' / f'{pid}.json', {
        'pid': pid, 'start': identity(pid), 'boot': marker['boot'], 'uid': marker['uid'], 'role': role})


def stop_registered(work):
    boot = current_boot()
    def stop(path):
        if path.is_symlink():
            raise ValueError('invalid process registration')
        group = json.loads(path.read_text())
        pid = group['pid']
        if type(pid) is not int or pid <= 1 or group['uid'] != os.getuid() or path.name != f'{pid}.json':
            raise ValueError('invalid process identity')
        if group['boot'] != boot:
            return  # host 重開機後不可對新開機的程序傳送訊號。 / Host reboot: never signal a new boot's processes.
        try:
            if identity(pid) != group['start']:
                return  # PID 重用時不可對新群組傳送訊號。 / PID reuse: do not signal the new process group.
        except FileNotFoundError:
            pass  # 已登記群組可能比原領導程序存活更久。 / A registered group can outlive its original leader.
        terminate_group(pid)
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


def plan_digest(report, fields):
    """報告中計畫欄位的雜湊；supervisor 經命令列交給 worker，不經磁碟。 / Digest of a report's plan fields. The
    supervisor hands it to the worker on the command line, never through the report on disk."""
    plan = {key: report.get(key) for key in fields}
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def plan_changed(report, planned):
    """報告中的計畫欄位是否與 supervisor 持有的值不同。 / Whether the report's plan fields differ from the values the
    supervisor holds."""
    return any(report.get(key) != value for key, value in planned.items())


# 監督結果的種類；停止原因也使用其中三個。 / The supervision outcome kinds; three of them are also stop reasons.
EXITED, TIMEOUT, CANCELLED, SUPERVISOR_FAILED, CLEANUP_FAILED = (
    'EXITED', 'TIMEOUT', 'CANCELLED', 'SUPERVISOR_FAILED', 'CLEANUP_FAILED')


class PlanMismatch(ValueError):
    """worker 報告與 supervisor 的計畫不同。 / The worker's report differs from the supervisor's plan."""


class _SupervisedRun:
    """supervise 內部的一次受監督執行狀態：收到的訊號、停止原因、例外型別與群組停止結果。

The internal state of one supervised run in supervise: signals received, the stop reason, the exception type
    and whether every registered group was stopped.
    """

    def __init__(self, root, run_id, work, max_seconds):
        self.root, self.run_id, self.work = root, run_id, work
        self.started = time.monotonic()
        self.deadline = self.started + max_seconds
        self.cancelled = []
        self.process = None
        self.first_stop = None
        self.error_type = None
        self.stop_error = None

    @property
    def returncode(self):
        return self.process.returncode if self.process is not None else None

    def run(self, command, env):
        """經閘門啟動 worker，持久登記後才放行，等待結束、期限或訊號，最後停止所有登記的群組。

Start the worker through the gate, release it only after durable registration, wait for its
        exit, the deadline or a signal, then stop every registered group.
        """
        try:
            self.process = subprocess.Popen(
                gated_command(command), cwd=self.root, start_new_session=True, stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={**env, 'TMPDIR': str(temporary_directory(self.run_id))})
            register_group(self.work, self.process.pid, role='worker')
            self.process.stdin.write(b'G')
            self.process.stdin.close()
            while self.process.poll() is None:
                if self.cancelled:
                    self.first_stop = CANCELLED
                    break
                if time.monotonic() >= self.deadline:
                    self.first_stop = TIMEOUT
                    break
                time.sleep(0.02)
        except Exception as exc:
            self.first_stop, self.error_type = SUPERVISOR_FAILED, type(exc).__name__
        finally:
            self.terminate()

    @property
    def stop(self):
        """目前的停止原因：最早觀察到的原因不被改寫；worker 自行結束後才收到的訊號仍阻止發布成功。

The current stop reason. The first reason observed is never rewritten; a signal after the worker exited on its own
        still keeps success unpublished.
        """
        return self.first_stop or (CANCELLED if self.cancelled else None)

    def terminate(self):
        process = self.process
        # 尚未登記的閘門子程序仍由此 Popen handle 擁有。 / Even an unregistered gated child is owned by this Popen handle.
        if process is not None:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            try:
                if process.returncode is None:
                    terminate_group(process.pid)
            except Exception as exc:
                self.stop_error = type(exc).__name__
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # 群組終止後仍存活的 worker 不可略過後續收尾。 / A worker that outlives its group kill must not skip
                # finalization.
                self.first_stop = self.first_stop or SUPERVISOR_FAILED
                self.error_type = self.error_type or 'TimeoutExpired'
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        try:
            stop_registered(self.work)
        except Exception as exc:
            self.stop_error = self.stop_error or type(exc).__name__


@contextmanager
def _supervised_run(root, run_id, operation, max_seconds, ceiling):
    """驗證期限、建立並持久登記執行，於收尾期間安裝訊號處理器；離開時還原。

Validate the deadline, create and durably register the run, and keep signal handlers
    installed through finalization; restore them on exit.
    """
    if (type(max_seconds) not in (int, float) or not math.isfinite(max_seconds)
            or not 0 < max_seconds <= ceiling):
        raise ValueError('invalid supervisor deadline')
    run = _SupervisedRun(root, run_id, prepare_run(root, run_id, operation), max_seconds)
    handlers = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, lambda number, frame: run.cancelled.append(number))
        yield run
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


class CleanupLockUnavailable(RuntimeError):
    """另一個程序正持有此執行的清理鎖。 / Another process holds this run's cleanup lock."""


class Outcome(NamedTuple):
    """監督結果：一次受監督執行如何結束，以及清理做到哪裡。

The supervision outcome: how one supervised run ended and how far its cleanup got.
    """
    # TIMEOUT、CANCELLED、SUPERVISOR_FAILED；worker 自行結束時為 None。 / TIMEOUT, CANCELLED or SUPERVISOR_FAILED;
    # None when the worker exited on its own.
    stop: str | None
    returncode: int | None
    error_type: str | None
    cleanup: dict
    seconds: float

    @property
    def kind(self):
        """清理失敗優先，其次是停止原因，最後才是 worker 自行結束。 / Cleanup failure first, then the stop reason, and
        only then a worker that exited on its own."""
        if not self.cleanup['completed']:
            return CLEANUP_FAILED
        return self.stop or EXITED


def remove_run(root, run_id):
    """刪除自己擁有的暫存目錄與執行清冊；兩者都不可是 symlink。

Remove the run's own temporary directory and run inventory. Neither may be a symlink.
    """
    work, temporary = run_directory(root, run_id), temporary_directory(run_id)
    if work.is_symlink() or temporary.is_symlink():
        raise ValueError('invalid run directory')
    if work.exists():
        marker = json.loads((work / 'owner.json').read_text())
        if marker['run_id'] != run_id or marker['uid'] != os.getuid():
            raise ValueError('run ownership mismatch')
    if temporary.exists():
        shutil.rmtree(temporary)
    if work.exists():
        shutil.rmtree(work)


class Ended(NamedTuple):
    """在 supervise 之外結束的 worker：停止原因與結束碼；介面與 supervise 內部的執行狀態相同。

A worker that ended outside supervise: its stop reason and exit code, with the same interface as the run state
    inside supervise.
    """
    stop: str | None
    returncode: int | None
    started: float
    error_type: str | None = None
    stop_error: str | None = None


def close_run(root, run_id, role, ended, marker=None):
    """在已持有的清理鎖下執行收尾協定：停止群組、清除角色的外部資源、寫阻擋檢查點、刪執行清冊，再寫最終證據；
回傳最終監督結果與角色的結果。ended 提供停止原因、結束碼、例外型別與開始時間；停止原因每次寫入前重新讀取。

Run the finalization protocol under the cleanup lock the caller holds: stop the groups, release the role's external
    resources, write a blocking checkpoint, remove the run inventory, then write the final evidence. Return the final
    outcome and the role's result. ended supplies the stop reason, exit code, exception type and start time; the stop
    reason is read again before each write.
    """
    work, temporary = run_directory(root, run_id), temporary_directory(run_id)
    errors = [ended.stop_error] if ended.stop_error else []
    groups_stopped = ended.stop_error is None
    try:
        stop_registered(work)
    except Exception as exc:
        groups_stopped = False
        errors.append(type(exc).__name__)
    try:
        role.release(run_id)
    except Exception as exc:
        errors.append(type(exc).__name__)
    # 群組停止後，worker 才無法繼續覆寫證據。 / Workers can no longer overwrite evidence after their groups are stopped.
    evidence = role.read()

    def outcome(completed):
        cleanup = {'completed': completed, 'error_type': errors[0] if errors else None,
                   'temporary_directory_removed': not temporary.exists(), 'run_directory_removed': not work.exists(),
                   'process_group_terminated': groups_stopped, 'recovered_by_janitor': marker is not None}
        if marker is not None:
            cleanup['boot_changed'] = marker['boot'] != current_boot()
        return Outcome(ended.stop, ended.returncode, ended.error_type, cleanup,
                       round(time.monotonic() - ended.started, 3))

    try:
        role.close(evidence, outcome(False))
    except Exception as exc:
        errors.append(type(exc).__name__)
    # 沒有阻擋檢查點，或任何清理步驟失敗時，保留執行清冊交給 janitor。 / Without a blocking checkpoint, or after any
    # failed cleanup step, keep the run inventory for the janitor.
    if not errors:
        try:
            remove_run(root, run_id)
        except Exception as exc:
            errors.append(type(exc).__name__)
    final = outcome(not errors)
    return final, role.close(evidence, final)


@contextmanager
def finalization_lock(work):
    """收尾所需的清理鎖；另一個程序持有時拋出 CleanupLockUnavailable，證據與執行清冊都不碰。

The cleanup lock finalization needs. When another process holds it, raise CleanupLockUnavailable and touch neither
    the evidence nor the run inventory.
    """
    with cleanup_lock(work) as locked:
        if not locked:
            raise CleanupLockUnavailable('run cleanup lock unavailable')
        yield


def supervise(root, run_id, role, command, env, max_seconds):
    """在一次受監督執行中跑 worker 並收尾；回傳角色最後一次關閉證據的結果。

Run the worker in one supervised run and finalize it. Return the role's final closing of the evidence.

    角色提供 operation、ceiling、release(run_id) 清除外部資源、read() 讀回 worker 證據，以及 close(evidence,
    outcome)。read 遇到無法讀取的證據時須回傳阻擋用的替代證據而不是拋出例外，否則執行清冊會一直保留。close 先以阻擋
    檢查點、再以最終監督結果各呼叫一次，所以只能由這兩個引數推導結果。 / The role provides operation, ceiling,
    release(run_id) for its external resources, read() for the worker's evidence and close(evidence, outcome). read
    must return blocking stand-in evidence for evidence it cannot read rather than raise, or the run inventory stays
    forever. close runs first with a blocking checkpoint and then with the final outcome, so it must derive everything
    from those two arguments.
    """
    with _supervised_run(root, run_id, role.operation, max_seconds, role.ceiling) as run:
        run.run(command, env)
        with finalization_lock(run.work):
            return close_run(root, run_id, role, run)[1]


def recover(root, run_id, marker, role):
    """在 sweep_runs 已持有的清理鎖下，以取消收尾擁有者已死亡的執行；清理未完成時拋出例外。

Finalize a run whose owner died as cancelled, under the cleanup lock sweep_runs already holds. Raise when cleanup is
    incomplete.
    """
    final, _ = close_run(root, run_id, role, Ended(CANCELLED, None, time.monotonic()), marker)
    if not final.cleanup['completed']:
        raise RuntimeError('run cleanup incomplete')


def sweep_runs(root, recoverers):
    """依擁有者標記的 operation 回收擁有者已死亡的執行；回傳已回收的 run ID 與失敗清單。

Reap the runs whose owner died, dispatching on the owner marker's operation. Return the
    reaped run IDs and the failures.
    """
    cleaned, failures = [], []
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
            if owner_alive(marker):
                continue
            reap = recoverers.get(marker.get('operation'))
            if reap is None:
                raise ValueError('unknown run operation')
            with cleanup_lock(work) as locked:
                if locked:
                    # 回收失敗時拋出例外，由下方記為失敗。 / A failed reap raises and is recorded as a failure below.
                    reap(root, work.name, marker)
                    cleaned.append(work.name)
        except Exception as exc:
            # 繼續回收其他執行；每個失敗均回報，但不保存原文。 / Keep reaping the remaining runs; report every failure, without its text.
            failures.append({'run_id': work.name, 'error_type': type(exc).__name__})
    return cleaned, failures
