#!/usr/bin/env python3
"""有限額的模型 worker；只有父程序可於清理後發布 COMPLETE。

Bounded model worker; only its parent may publish COMPLETE after cleanup."""
import asyncio
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.lifecycle import run_directory
from security_harness.limits import MODEL_WORKER_RLIMITS, apply_rlimits
from scripts.model_smoke import run_worker

if __name__ == '__main__':
    if (len(sys.argv) not in (3, 5) or
            (len(sys.argv) == 5 and (sys.argv[3] != 'blind-review' or not re.fullmatch(r'[0-9a-f]{64}', sys.argv[4])))):
        # 未知模式不可默默改跑 smoke worker；盲審須附 supervisor 的計畫摘要。 / An unknown mode must not silently
        # run the smoke worker, and a blind review must carry the supervisor's plan digest.
        raise SystemExit('usage: model_worker.py ROOT RUN_ID [blind-review PLAN_SHA256]')
    root, run_id = Path(sys.argv[1]), sys.argv[2]
    run_directory(root, run_id)
    apply_rlimits(MODEL_WORKER_RLIMITS)
    if len(sys.argv) == 5:
        from security_harness.llm.benchmark_runner import run_worker as review_worker
        raise SystemExit(asyncio.run(review_worker(root, run_id, plan_digest=sys.argv[4])))
    raise SystemExit(asyncio.run(run_worker(root, run_id)))
