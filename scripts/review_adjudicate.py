#!/usr/bin/env python3
"""Append an unsigned, report-bound human note; never alter gates or reference labels."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.llm.benchmark_score import add_adjudication

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--case', required=True)
    parser.add_argument('--decision', choices=('REFERENCE_CONFIRMED', 'REFERENCE_CHALLENGED', 'NEEDS_MORE_EVIDENCE'), required=True)
    parser.add_argument('--reviewer', required=True, help='asserted local reviewer label; identity is not authenticated')
    parser.add_argument('--reason', required=True)
    args = parser.parse_args()
    try:
        path = add_adjudication(args.report, args.case, args.decision, args.reviewer, args.reason)
    except Exception:
        parser.exit(1, 'Invalid or unavailable report/adjudication; no note accepted.\n')
    print(path)
