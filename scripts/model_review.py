#!/usr/bin/env python3
"""Collect blind synthetic reviews; COMPLETE describes execution, never safety."""
import argparse
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.llm.benchmark import PROVIDERS, SUITES, load_cases
from security_harness.llm.benchmark_runner import initial_report
from security_harness.llm.lifecycle import persist, supervise
from scripts.model_smoke import require_model_roe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=PROVIDERS, action='append')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--case', choices=tuple(load_cases()), action='append')
    selection.add_argument('--suite', choices=(*SUITES, 'all'),
                           help='default: injection; boundaries selects B07-B12; all still obeys budgets')
    parser.add_argument('--rounds', type=int, choices=range(1, 5), default=1,
                        help='planned repetitions share the same total call/token/time caps')
    parser.add_argument('--live', action='store_true', help='permit selected live API calls for fixed synthetic cases')
    parser.add_argument('--output-tokens', type=int, choices=(512, 1024), default=512,
                        help='per-review reservation; total must remain <=8192 tokens')
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
    path = ROOT / 'artifacts' / report['run_id'] / 'report.json'
    persist(path, report)
    data = supervise(ROOT, report, [sys.executable, '-I', str(ROOT / 'scripts/model_worker.py'),
                                  str(ROOT), report['run_id'], 'blind-review'], report['total_timeout_seconds'])
    print(json.dumps({'status': data['status'], 'advisory_only': True, 'evidence': str(path),
                      'bias_reduction': 'NOT_ESTABLISHED'}))
    return 0 if data['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
