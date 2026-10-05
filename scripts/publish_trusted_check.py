#!/usr/bin/env python3
"""Run only in the independently controlled publisher deployment."""
import argparse
import fcntl
import hashlib
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.results import write_json
from security_harness.trusted_publisher import Denied, installation_client, need, publish, strict_json, validate_settings


def read_config(path, live):
    path = Path(path).absolute()
    if live:
        need(not path.resolve(strict=True).is_relative_to(ROOT.resolve())
             and not path.is_symlink(), "CONFIG_MUST_BE_EXTERNAL")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= 1024**2, "CONFIG_FILE")
        if live:
            need(not info.st_mode & 0o022, "CONFIG_WRITABLE")
        return stream.read(1024**2 + 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--gate-policy", type=Path, required=True)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {"decision": "BLOCK", "code": "NOT_STARTED", "deployed": False}
    lock_fd = None
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
            need(args.lock_file is not None and not args.lock_file.resolve().is_relative_to(ROOT.resolve()), "EXTERNAL_LOCK_REQUIRED")
            lock_fd = os.open(args.lock_file, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            need(stat.S_ISREG(os.fstat(lock_fd).st_mode), "LOCK_FILE")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            client = installation_client(settings, args.private_key)
            result = publish(client, settings, gate_policy, args.pr, args.run_id)
            result["deployed"] = False  # A one-shot check does not certify a running deployment.
    except Exception as exc:
        result.update(decision="BLOCK", code=str(exc) if isinstance(exc, Denied) else "PUBLISHER_ERROR")
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
    if args.output:
        write_json(args.output, result)
    import json
    print(json.dumps(result))
    return 0 if result["decision"] == "ALLOW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
