#!/usr/bin/env python3
"""執行固定合成 gateway 測試；真實呼叫必須明確啟用。

Run the fixed synthetic gateway fixture. Live calls are explicit opt-in."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from security_harness.llm import config
from security_harness.llm.lifecycle import (FIXTURE as FIXTURE, initial_smoke_report,
                                            plan_smoke, require_model_roe, run_worker as run_worker)

# 計畫生命週期位於函式庫；此處保留名稱供 CLI 與既有匯入使用。 / The plan lifecycle lives in the library; the name
# is re-exported for the CLI and existing imports.
initial_report = initial_smoke_report


def configured_adapter(provider, roe_sha256, work=None, http=None):
    return config.configured_adapter(provider, roe_sha256, work, http)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("mock", "gemini", "bedrock", "glm", "deepseek", "lmstudio"), action="append",
                        help='可重複指定；真實供應商需 --live / repeatable; live providers need --live')
    parser.add_argument("--live", action="store_true", help="允許選定供應商執行固定合成測試 / permit selected live providers for the fixed synthetic fixture")
    parser.add_argument("--output", type=Path,
                        help='另存報告的路徑 / extra copy of the report')
    args = parser.parse_args()
    providers = args.provider or ["mock"]
    if len(providers) != len(set(providers)):
        parser.error("duplicate providers are not allowed")
    if any(p != "mock" for p in providers) and not args.live:
        parser.error("live providers require --live")
    if args.live:
        require_model_roe(parser, providers, sum(p != "mock" for p in providers))
    run = plan_smoke(providers, root=ROOT)
    output = args.output or run.path
    if output.exists():
        parser.error("output already exists; choose a new evidence path")
    run.record(extra_output=args.output)
    data = run.supervise()
    print(json.dumps({'status': data['status'], 'checks': data['checks'], 'evidence': str(run.path)}))
    return 0 if data['status'] == 'COMPLETE' else 1


if __name__ == "__main__":
    raise SystemExit(main())
