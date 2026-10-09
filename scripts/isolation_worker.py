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
        print(type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
