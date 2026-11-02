"""持久化操作意圖與恢復資料。只儲存經查核的公開 GitHub 資料，不儲存權杖。"""
import fcntl
import json
import os
import stat
import sys
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4


def recovery_warning(message):
    """盡力輸出固定恢復告警；Best-effort fixed recovery diagnostic output."""
    try:
        print(message, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


def sync_json(path, value):
    temporary = path.with_name(path.name+'.'+uuid4().hex+'.pending')
    with temporary.open('x', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Journal:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.path = self.directory / 'events.jsonl'
        self.path.touch(mode=0o600)

    @classmethod
    def resume(cls, directory, *, preserve_events=False):
        instance = cls.__new__(cls)
        instance.directory = Path(directory)
        instance.path = instance.directory/'events.jsonl'
        info = instance.directory.stat()
        if (instance.directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid() or info.st_mode & 0o077
                or instance.path.is_symlink() or (instance.path.exists() and not instance.path.is_file())):
            raise ValueError('JOURNAL_PATH')
        if preserve_events:
            instance.path = instance.directory/('recovery-events-'+uuid4().hex+'.jsonl')
            try:
                instance.path.touch(mode=0o600, exist_ok=False)
            except OSError:
                pass  # 私有側錄無法建立時仍可恢復。 / Recovery must survive unavailable logging.
        elif not instance.path.is_file():
            raise ValueError('JOURNAL_PATH')
        return instance

    def record(self, event, **data):
        value = {'time': datetime.now(timezone.utc).isoformat(), 'event': event, **data}
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a', encoding='utf-8') as stream:
            stream.write(json.dumps(value, ensure_ascii=False) + '\n')
            stream.flush()
            os.fsync(stream.fileno())

    def save(self, name, data):
        sync_json(self.directory / name, data)


    def save_bytes(self, name, raw):
        path = self.directory/name
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class ProtectedRemote:
    def __init__(self, remote, journal):
        self.remote, self.journal = remote, journal
        self.saved = False

    def observe(self, **kwargs):
        snapshot = self.remote.observe(**kwargs)
        if not self.saved:
            self.journal.save('recovery.json', {'ruleset': snapshot['ruleset']})
            self.original = snapshot['ruleset']
            self.saved = True
        self.journal.record('observation', snapshot=snapshot)
        return snapshot

    def set_ruleset(self, payload):
        if not self.saved:
            raise RuntimeError('RECOVERY_NOT_SAVED')
        restoring = payload == self.original
        try:
            self.journal.record('write_intent', operation='ruleset', payload=payload)
        except OSError:
            if not restoring:
                raise
            recovery_warning('RECOVERY_JOURNAL_UNAVAILABLE: continuing restore')
        self.remote.set_ruleset(payload)
        try:
            self.journal.record('write_returned', operation='ruleset')
        except OSError:
            if not restoring:
                raise

    def read_ruleset(self, **kwargs):
        value = self.remote.read_ruleset(**kwargs)
        try:
            self.journal.record('ruleset_readback', ruleset=value)
        except OSError:
            recovery_warning('RECOVERY_READBACK_JOURNAL_UNAVAILABLE')
        return value

    def merge(self, head):
        self.journal.record('write_intent', operation='merge', head=head)
        return self.remote.merge(head)

    def inspect_outcome(self):
        value = self.remote.inspect_outcome()
        self.journal.record('outcome', outcome=value)
        return value


class ProcessLock:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        self.stream = os.fdopen(descriptor, 'r+')
        try:
            fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.stream.close()
            raise RuntimeError('ALREADY_RUNNING') from None
        return self

    def __exit__(self, *args):
        self.stream.close()


from contextlib import contextmanager
import signal
from contextvars import ContextVar

_restoring = ContextVar("restoring", default=False)


@contextmanager
def recovery_signals():
    token = _restoring.set(True)
    try:
        yield
    finally:
        _restoring.reset(token)


@contextmanager
def termination_guard():
    received = 0
    def terminate(signum, frame):
        nonlocal received
        received += 1
        if _restoring.get() and received == 1:
            recovery_warning('RECOVERY_CONTINUES_AFTER_SIGTERM')
            return
        raise KeyboardInterrupt('SIGTERM')
    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)
