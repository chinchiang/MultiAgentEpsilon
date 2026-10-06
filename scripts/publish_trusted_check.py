#!/usr/bin/env python3
"""Run only in the independently controlled publisher deployment."""
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
sys.path.insert(0, str(ROOT))
from security_harness.results import write_json
from security_harness.trusted_publisher import Denied, installation_client, need, publish, strict_json, validate_settings

MAX_CACHED_BLOBS = 20000


def read_config(path, live, owner_uid=0):
    path = Path(path).absolute()
    if live:
        need(not path.resolve(strict=True).is_relative_to(ROOT.resolve())
             and not path.is_symlink(), "CONFIG_MUST_BE_EXTERNAL")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 1024**2, "CONFIG_FILE")
        if live:
            # The service account must not be able to rewrite its own trust policy.
            need(not info.st_mode & 0o022 and info.st_uid == owner_uid, "CONFIG_WRITABLE")
        return stream.read(1024**2 + 1)


def load_state(path):
    """Corrupt or foreign state is discarded, never trusted: it only caches
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
        pass  # Best effort; the token still expires within an hour.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--gate-policy", type=Path, required=True)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--state-file", type=Path)
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--output", type=Path)
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
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
            result["deployed"] = False  # A one-shot check does not certify a running deployment.
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
