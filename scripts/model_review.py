#!/usr/bin/env python3
"""收集合成案例的盲審；COMPLETE 只描述執行完成，不代表安全。

Collect blind synthetic reviews; COMPLETE describes execution, never safety."""
import argparse
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.llm.benchmark import PROVIDERS, SUITES, load_cases
from security_harness.llm.benchmark_runner import initial_report
from security_harness.llm.lifecycle import persist, supervise
from scripts.model_smoke import require_model_roe


def deadline_warning(live_calls, total_seconds, per_call_seconds=30):
    """付費呼叫前提醒：最壞情況的逐次期限總和超過整輪上限時，慢回應會留下 INCOMPLETE。

Before paid calls: if per-call deadlines can exceed the run cap, slow replies leave INCOMPLETE."""
    worst = live_calls * per_call_seconds
    if worst <= total_seconds:
        return None
    return (f'最壞情況 {worst} 秒超過整輪上限 {total_seconds} 秒；回應較慢時結果會是 INCOMPLETE / '
            f'worst case {worst}s exceeds the {total_seconds}s run cap; slow replies will leave the run INCOMPLETE')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=PROVIDERS, action='append',
                        help='可重複指定；預設兩個 mock 審查者 / repeatable; defaults to two mock reviewers')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--case', choices=tuple(load_cases()), action='append',
                           help='可重複指定的案例 ID / repeatable case ID')
    selection.add_argument('--suite', choices=(*SUITES, 'all'),
                           help='預設 injection；boundaries 為 B07–B12，variants 為 B13–B16；all 仍受預算限制 / default: injection; boundaries selects B07-B12, variants B13-B16; all still obeys budgets')
    parser.add_argument('--rounds', type=int, choices=range(1, 5), default=1,
                        help='所有輪次共用呼叫、詞元及時間總上限 / planned repetitions share the same total call/token/time caps')
    parser.add_argument('--live', action='store_true', help='允許選定真實 API 處理固定合成案例 / permit selected live API calls for fixed synthetic cases')
    parser.add_argument('--output-tokens', type=int, choices=(512, 1024), default=512,
                        help='每筆審查預留量，合計不得超過 8192 詞元 / per-review reservation; total must remain <=8192 tokens')
    args = parser.parse_args()
    providers = args.provider or ['mock-review-a', 'mock-review-b']
    if any(not p.startswith('mock-') for p in providers) and not args.live:
        parser.error('live providers require --live')
    cases = args.case or (list(load_cases()) if args.suite == 'all' else list(SUITES[args.suite or 'injection']))
    if args.live:
        live = sum(not p.startswith('mock-') for p in providers)
        require_model_roe(parser, providers, live * len(cases) * args.rounds)
    try:
        report = initial_report(providers, cases, str(uuid.uuid4()), args.output_tokens, args.rounds)
    except ValueError:
        parser.error('use unique providers/cases, at most 16 reviews and at most 8192 reserved output tokens')
    if args.live:
        warning = deadline_warning(sum(not p.startswith('mock-') for p in providers) * len(cases) * args.rounds,
                                   report['total_timeout_seconds'])
        if warning:
            print(warning, file=sys.stderr)
    path = ROOT / 'artifacts' / report['run_id'] / 'report.json'
    persist(path, report)
    data = supervise(ROOT, report, [sys.executable, '-I', str(ROOT / 'scripts/model_worker.py'),
                                  str(ROOT), report['run_id'], 'blind-review'], report['total_timeout_seconds'])
    print(json.dumps({'status': data['status'], 'advisory_only': True, 'evidence': str(path),
                      'bias_reduction': 'NOT_ESTABLISHED'}))
    return 0 if data['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
