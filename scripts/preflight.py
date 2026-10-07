#!/usr/bin/env python3
"""Dependency-free preflight with an early-error audit envelope."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.audit import AuditRun
from security_harness.preflight import verify
from security_harness.results import digest_file, subject_digest, write_json


def main():
    audit = AuditRun(ROOT, "preflight")
    output = None
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--output", type=Path)
        output = parser.parse_args().output
        audit.stage("configuration")
        policy_file = ROOT / "security/policy.json"
        policy = json.loads(policy_file.read_text())
        audit.data["policy_digest"] = digest_file(policy_file)
        audit.data["subject_digest"] = subject_digest(ROOT)
        audit.stage("G1")
        packages = verify(ROOT / "requirements.lock", policy)
        audit.add("G1", "COMPLETED", "scan", len(packages), 0, "metadata checks only", packages=packages)
        audit.data.update(decision="ALLOW", reasons=[])
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
    code = audit.finish((("G1", "scan"),))
    if output:
        write_json(output, audit.data)
    print(f"Preflight {audit.data['decision']}: {audit.output / 'report.json'}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
