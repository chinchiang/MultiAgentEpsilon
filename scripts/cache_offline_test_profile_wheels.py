#!/usr/bin/env python3
"""下載鎖定的離線測試 wheel 快取。 / Fetch the pinned offline-test wheel cache."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from security_harness.offline_test_profile import cache_wheels


def main() -> int:
    count = cache_wheels()
    print(json.dumps({"status": "VERIFIED_WHEEL_CACHE", "wheels": count}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
