#!/usr/bin/env python3
"""可信完整管線 worker；期限與清理由監督程序管理。

Trusted whole-pipeline worker; the supervisor owns deadlines and cleanup."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.lifecycle import resume_worker
from scripts.run_security import main


if __name__ == '__main__':
    if len(sys.argv) != 3 or not re.fullmatch(r'[0-9a-f]{64}', sys.argv[2]):
        # 候選與版本只從計畫讀取，不另走命令列。 / The candidate and variant come from the plan only, never argv.
        raise SystemExit('usage: security_worker.py RUN_ID PLAN_SHA256')
    run_id, digest = sys.argv[1:]
    raise SystemExit(main(resume_worker(ROOT, run_id, digest), defer_final=True))
