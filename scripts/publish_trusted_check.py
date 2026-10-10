#!/usr/bin/env python3
"""只能在獨立受控的發布器部署環境執行。

Run only in the independently controlled publisher deployment."""
import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.results import write_json
from security_harness.trusted_publisher import (Denied, installation_client, need, open_config, publish, strict_json,
                                               validate_settings)

MAX_CACHED_BLOBS = 20000


def read_config(path, live, owner_uid=0):
    path = Path(path).absolute()
    if live:
        need(not path.resolve(strict=True).is_relative_to(ROOT.resolve())
             and not path.is_symlink(), "CONFIG_MUST_BE_EXTERNAL")
    fd = open_config(path, owner_uid) if live else os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 1024**2, "CONFIG_FILE")
        if live:
            # 服務帳號不可重寫自身信任政策。 / The service account must not be able to rewrite its own trust policy.
            need(not info.st_mode & 0o022 and info.st_uid == owner_uid, "CONFIG_WRITABLE")
        return stream.read(1024**2 + 1)


def load_state(path):
    """損壞或外來狀態一律丟棄；狀態只快取按內容定址的摘要與此發布器上次結果，不作為信任來源。

Corrupt or foreign state is discarded, never trusted: it only caches
    content-addressed digests and the last outcome this publisher posted."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 4 * 1024**2:
            return {}
        try:
            state = strict_json(stream.read())
        except (ValueError, UnicodeError):
            return {}
    if not isinstance(state, dict):
        return {}
    blobs = state.get("blobs")
    if (not isinstance(blobs, dict) or len(blobs) > MAX_CACHED_BLOBS or
            not all(re.fullmatch(r"[0-9a-f]{40}", k) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                    for k, v in blobs.items())):
        state["blobs"] = {}
    if type(state.get("backoff_until")) is not int:
        state.pop("backoff_until", None)
    if not isinstance(state.get("published"), dict):
        state.pop("published", None)
    return state


def save_state(path, state):
    if len(state.get("blobs", {})) > MAX_CACHED_BLOBS:
        state["blobs"] = {}
    write_json(Path(path), state)


def revoke(client):
    try:
        client.raw("https://api.github.com/installation/token", "DELETE")
    except Exception:
        pass  # 盡力撤銷；權杖本身仍會在一小時內到期。 / Best effort; the token still expires within an hour.


LOCK_WAIT_SECONDS = 60


def acquire_lock(fd, wait=LOCK_WAIT_SECONDS, clock=time.monotonic, sleep=time.sleep):
    """有限等待共用鎖；所有 PR 實例共用一把鎖，彼此排隊而不是立即失敗。

Wait a bounded time for the shared lock, so PR instances queue instead of failing at once."""
    deadline = clock() + wait
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if clock() >= deadline:
                raise Denied("LOCK_BUSY") from None
            sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True,
                        help='root 持有的發布器設定 / root-owned publisher settings')
    parser.add_argument("--gate-policy", type=Path, required=True,
                        help='已核准 evaluator 的政策副本 / policy copy from the approved evaluator')
    parser.add_argument("--private-key", type=Path,
                        help='App 私鑰（systemd credential 副本）/ App private key (systemd credential copy)')
    parser.add_argument("--pr", type=int,
                        help='要核對的 PR 編號 / pull request to reconcile')
    parser.add_argument("--run-id", type=int,
                        help='指定 workflow run；省略時選最新可信 run / specific workflow run; defaults to the latest trusted run')
    parser.add_argument("--lock-file", type=Path,
                        help='所有實例共用的鎖檔 / lock file shared by all instances')
    parser.add_argument("--state-file", type=Path,
                        help='此 PR 的快取與退避狀態 / cache and backoff state for this PR')
    parser.add_argument("--validate-config", action="store_true",
                        help='只驗證設定，不連線 GitHub / validate settings only; no GitHub access')
    parser.add_argument("--output", type=Path,
                        help='結果 JSON 路徑 / result JSON path')
    args = parser.parse_args()
    result = {"decision": "BLOCK", "code": "NOT_STARTED", "deployed": False}
    lock_fd = None
    state = None
    try:
        need(sys.version_info[:2] == (3, 12), "PYTHON_VERSION")
        live = not args.validate_config
        settings = strict_json(read_config(args.settings, live))
        raw_policy = read_config(args.gate_policy, live)
        gate_policy = strict_json(raw_policy)
        validate_settings(settings, gate_policy)
        need(hashlib.sha256(raw_policy).hexdigest() == settings["policy_digest"], "LOCAL_POLICY_DIGEST")
        if args.validate_config:
            result = {"decision": "ALLOW", "code": "CONFIG_VALID", "deployed": False}
        else:
            need(args.private_key is not None and args.pr is not None and args.pr > 0, "LIVE_ARGUMENTS")
            need(args.run_id is None or args.run_id > 0, "RUN_ID")
            need(not args.private_key.resolve(strict=True).is_relative_to(ROOT.resolve()), "KEY_MUST_BE_EXTERNAL")
            key_owner = args.private_key.lstat().st_uid
            need(key_owner in (0, os.getuid()), "PRIVATE_KEY_OWNER")
            for external in (args.lock_file, args.state_file):
                need(external is not None and not external.resolve().is_relative_to(ROOT.resolve()), "EXTERNAL_STATE_REQUIRED")
            lock_fd = os.open(args.lock_file, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            need(stat.S_ISREG(os.fstat(lock_fd).st_mode), "LOCK_FILE")
            acquire_lock(lock_fd)
            state = load_state(args.state_file)
            if state.get("backoff_until", 0) > time.time():
                result.update(code="THROTTLED_BACKOFF")
            else:
                state.pop("backoff_until", None)
                client = installation_client(settings, args.private_key)
                try:
                    result = publish(client, settings, gate_policy, args.pr, args.run_id, state)
                finally:
                    revoke(client)
            result["deployed"] = False  # 單次查核不代表服務已持續部署。 / A one-shot check does not certify a running deployment.
    except Exception as exc:
        result.update(decision="BLOCK", code=str(exc) if isinstance(exc, Denied) else "PUBLISHER_ERROR")
    finally:
        if state is not None:
            try:
                save_state(args.state_file, state)
            except Exception:
                result.update(decision="BLOCK", code="STATE_WRITE_FAILED")
        if lock_fd is not None:
            os.close(lock_fd)
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result))
    return 0 if result["decision"] == "ALLOW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
