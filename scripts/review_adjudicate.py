#!/usr/bin/env python3
"""追加未簽章且綁定報告的人工註記；不可變更閘門或標準答案。

Append an unsigned, report-bound human note; never alter gates or reference labels."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.llm.benchmark_score import add_adjudication, read_adjudications

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True,
                        help='盲測報告 report.json / blind-review report.json')
    parser.add_argument('--case',
                        help='案例 ID / case ID')
    parser.add_argument('--decision', choices=('REFERENCE_CONFIRMED', 'REFERENCE_CHALLENGED', 'NEEDS_MORE_EVIDENCE'),
                        help='人工判讀結果 / human adjudication outcome')
    parser.add_argument('--reviewer', help='自報本機審查者標籤，身分未驗證 / asserted local reviewer label; identity is not authenticated')
    parser.add_argument('--reason',
                        help='裁決理由（合成、無個資）/ adjudication reason (synthetic, no personal data)')
    parser.add_argument('--list-notes', action='store_true', help='驗證精確報告綁定並列出未簽章註記 / validate exact-report binding and list unsigned notes')
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
