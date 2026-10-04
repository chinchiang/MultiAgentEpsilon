#!/usr/bin/env python3
"""Detect protected changes against a trusted base; remote enforcement is separate.

In CI execute the base-ref copy of this file. A required trusted workflow/ruleset
must protect this job itself; candidate-controlled YAML cannot prove that property.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

PROTECTED = (".github/", "security/", "security_harness/", "scripts/", "tests/")
EXACT = {"requirements.in", "requirements.lock", "pyproject.toml"}


def protected_changes(names):
    return [name for name in names if name.startswith(PROTECTED) or name in EXACT]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.base):
        raise ValueError("base must be an immutable commit SHA")
    run = subprocess.run(["git", "-C", str(args.candidate), "diff", "--name-only", "-z", args.base, "HEAD"],
                         capture_output=True, check=True, timeout=20)
    changed = protected_changes([name for name in run.stdout.decode().split("\0") if name])
    print(json.dumps({"protected_changes": changed, "decision": "BLOCK" if changed else "ALLOW"}))
    return 1 if changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
