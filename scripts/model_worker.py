#!/usr/bin/env python3
"""有限額的模型 worker；只有父程序可於清理後發布 COMPLETE。

Bounded model worker; only its parent may publish COMPLETE after cleanup."""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.lifecycle import run_directory
from security_harness.limits import MODEL_WORKER_RLIMITS, apply_rlimits
from scripts.model_smoke import run_worker

if __name__ == '__main__':
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != 'blind-review'):
        # 未知模式不可默默改跑 smoke worker。 / An unknown mode must not silently run the smoke worker.
        raise SystemExit('usage: model_worker.py ROOT RUN_ID [blind-review]')
    root, run_id = Path(sys.argv[1]), sys.argv[2]
    run_directory(root, run_id)
    apply_rlimits(MODEL_WORKER_RLIMITS)
    if len(sys.argv) == 4:
        from security_harness.llm.benchmark_runner import run_worker
    raise SystemExit(asyncio.run(run_worker(root, run_id)))
