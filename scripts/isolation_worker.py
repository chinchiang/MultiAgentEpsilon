#!/usr/bin/env python3
"""可信子程序；候選程式只能在隔離容器內執行。

Trusted subprocess: candidate code is only executed inside isolation containers."""
import json
import sys
from pathlib import Path
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_harness.isolation import run_isolated

if __name__ == "__main__":
    try:
        print(json.dumps(run_isolated(Path(sys.argv[1]), sys.argv[2], sys.argv[3])))
    except Exception as exc:
        # 只輸出例外型別與不符的檢查名稱，不輸出例外文字。 / Only the exception type and failed check names, never its text.
        print(json.dumps({"error_type": type(exc).__name__, "failed_checks": getattr(exc, "failed", [])}))
        raise SystemExit(1)
