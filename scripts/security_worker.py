#!/usr/bin/env python3
"""可信完整管線 worker；期限與清理由父程序管理。

Trusted whole-pipeline worker; the parent owns deadlines and cleanup."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.audit import AuditRun
from security_harness.lifecycle import run_directory
from security_harness.limits import WORKER_RLIMITS, apply_rlimits
from scripts.run_security import main


if __name__ == '__main__':
    run_id, candidate, variant = sys.argv[1:]
    run_directory(ROOT, run_id)  # 先驗證，再解析證據路徑。 / validate before resolving evidence paths
    apply_rlimits(WORKER_RLIMITS)
    audit = AuditRun.resume(ROOT, run_id)
    sys.argv = ['run_security', '--candidate', candidate, '--variant', variant]
    raise SystemExit(main(audit=audit, defer_final=True))
