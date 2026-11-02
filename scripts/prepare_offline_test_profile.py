#!/usr/bin/env python3
"""準備可信離線補充測試的 Docker 建置內容。

Prepare the trusted offline supplemental-test build context.

Prepare the profile from this trusted checkout; candidate paths are not accepted.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security_harness.offline_test_profile import prepare


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="new Docker build context path / 新的 Docker 建置內容路徑")
    args = parser.parse_args()
    result = prepare(args.output)
    print(json.dumps({
        "status": "VERIFIED_OFFLINE_TEST_CONTEXT",
        "profile": result.profile,
        "context": str(result.context_path),
        "context_manifest_sha256": result.context_manifest_sha256,
        "profile_lock_sha256": result.profile_lock_sha256,
        "wheels": result.wheel_count,
        "runtime_packages": result.runtime_package_count,
        "published": False,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
