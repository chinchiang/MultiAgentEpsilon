#!/usr/bin/env python3
"""Append an unsigned, report-bound human note; never alter gates or reference labels."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.llm.benchmark_score import add_adjudication, read_adjudications

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--case')
    parser.add_argument('--decision', choices=('REFERENCE_CONFIRMED', 'REFERENCE_CHALLENGED', 'NEEDS_MORE_EVIDENCE'))
    parser.add_argument('--reviewer', help='asserted local reviewer label; identity is not authenticated')
    parser.add_argument('--reason')
    parser.add_argument('--list-notes', action='store_true', help='validate exact-report binding and list unsigned notes')
    args = parser.parse_args()
    try:
        if args.list_notes:
            if any((args.case, args.decision, args.reviewer, args.reason)):
                parser.error('--list-notes cannot create a new note')
            print(json.dumps({'identity_verified': False, 'notes': read_adjudications(args.report)}, ensure_ascii=False))
            raise SystemExit(0)
        if not all((args.case, args.decision, args.reviewer, args.reason)):
            parser.error('creating a note requires --case, --decision, --reviewer and --reason')
        path = add_adjudication(args.report, args.case, args.decision, args.reviewer, args.reason)
    except Exception:
        parser.exit(1, 'Invalid or unavailable report/adjudication; no note accepted.\n')
    print(path)
