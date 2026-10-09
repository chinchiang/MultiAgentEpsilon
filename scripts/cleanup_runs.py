#!/usr/bin/env python3
"""只回收目前 UID 擁有且 supervisor 已死亡的執行；不可清除其他仍存活的執行。

Reap only dead supervisor runs owned by this UID; never clear another live run."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.lifecycle import SweepIncomplete, sweep_stale

if __name__ == '__main__':
    try:
        print(json.dumps({'cleaned_run_ids': sweep_stale(ROOT)}))
    except SweepIncomplete as exc:
        # 其他過期執行仍已回收；失敗清單不保存原文。 / Every other stale run was still reaped; the failures are listed without text.
        print(json.dumps({'cleaned_run_ids': exc.cleaned, 'failed': exc.failures}))
        raise SystemExit(1)
