#!/usr/bin/env python3
"""可信完整管線 worker；期限與清理由父程序管理。

Trusted whole-pipeline worker; the parent owns deadlines and cleanup."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.audit import AuditRun
from security_harness.lifecycle import matches_plan
from security_harness.supervision import run_directory
from security_harness.limits import WORKER_RLIMITS, apply_rlimits
from scripts.run_security import main


if __name__ == '__main__':
    if len(sys.argv) != 3 or not re.fullmatch(r'[0-9a-f]{64}', sys.argv[2]):
        # 候選與版本只從計畫讀取，不另走命令列。 / The candidate and variant come from the plan only, never argv.
        raise SystemExit('usage: security_worker.py RUN_ID PLAN_SHA256')
    run_id, digest = sys.argv[1:]
    run_directory(ROOT, run_id)  # 先驗證，再解析證據路徑。 / validate before resolving evidence paths
    apply_rlimits(WORKER_RLIMITS)
    audit = AuditRun.resume(ROOT, run_id)
    if not matches_plan(audit.data, digest):
        # 計畫已不可信：不在這份報告上寫任何東西。 / The plan is no longer trusted: write nothing to this report.
        raise SystemExit(2)
    raise SystemExit(main(audit, defer_final=True))
