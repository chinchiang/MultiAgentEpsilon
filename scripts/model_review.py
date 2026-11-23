#!/usr/bin/env python3
"""收集合成案例的盲審；COMPLETE 只描述執行完成，不代表安全。

Collect blind synthetic reviews; COMPLETE describes execution, never safety."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.llm.benchmark import OUTPUT_BUDGETS, PROVIDERS, SUITES, load_cases
from security_harness.llm.lifecycle import plan_review, require_model_roe


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
    parser.add_argument('--output-tokens', type=int, choices=OUTPUT_BUDGETS, default=512,
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
        run = plan_review(providers, cases, output_tokens=args.output_tokens, rounds=args.rounds, root=ROOT)
    except ValueError:
        parser.error('use unique providers/cases, at most 16 reviews and at most 8192 reserved output tokens')
    if args.live and run.deadline_warning:
        print(run.deadline_warning, file=sys.stderr)
    data = run.supervise()
    print(json.dumps({'status': data['status'], 'advisory_only': True, 'evidence': str(run.path),
                      'bias_reduction': 'NOT_ESTABLISHED'}))
    return 0 if data['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
