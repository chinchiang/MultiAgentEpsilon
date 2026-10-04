#!/usr/bin/env python3
"""Can run before application dependencies are installed."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.preflight import verify
from security_harness.results import digest_file, result, subject_digest, write_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/preflight.json")
    args = parser.parse_args()
    policy_file = ROOT / "security/policy.json"
    policy = json.loads(policy_file.read_text())
    subject = subject_digest(ROOT)
    try:
        checked = verify(ROOT / "requirements.lock", policy)
        data = result("G1", "COMPLETED", "scan", len(checked), 0, subject,
                      digest_file(policy_file), "registry identity, hashes, age and wheel availability verified",
                      packages=checked, limitations=["no CVE or malicious-behavior analysis"])
        code = 0
    except Exception as exc:
        # Exception type only: network errors can contain proxy credentials or sensitive URLs.
        data = result("G1", "ERROR", "scan", 0, 0, subject, digest_file(policy_file),
                      "preflight could not establish required evidence", error_type=type(exc).__name__)
        code = 2
    write_json(args.output, data)
    print(f"G1 {data['execution']}: {data['coverage_count']} packages; report {args.output}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
