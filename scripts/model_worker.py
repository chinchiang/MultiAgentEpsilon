#!/usr/bin/env python3
"""有限額的模型 worker；只有 supervisor 可於清理後發布 COMPLETE。

Bounded model worker; only the supervisor may publish COMPLETE after cleanup."""
import asyncio
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.limits import MODEL_WORKER_RLIMITS, apply_rlimits
from security_harness.llm.lifecycle import run_worker
from security_harness.supervision import run_directory

if __name__ == '__main__':
    if (len(sys.argv) != 5 or sys.argv[3] not in ('smoke', 'blind-review')
            or not re.fullmatch(r'[0-9a-f]{64}', sys.argv[4])):
        # 每種模式都須附 supervisor 的計畫摘要；未知模式不可默默改跑其他 worker。 / Every mode carries the
        # supervisor's plan digest, and an unknown mode must not silently run another worker.
        raise SystemExit('usage: model_worker.py ROOT RUN_ID {smoke|blind-review} PLAN_SHA256')
    root, run_id, mode, digest = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    run_directory(root, run_id)
    apply_rlimits(MODEL_WORKER_RLIMITS)
    raise SystemExit(asyncio.run(run_worker(root, run_id, plan_digest=digest, mode=mode)))
