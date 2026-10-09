#!/usr/bin/env python3
"""核對並彙整分批盲審；Validate and summarize batched blind reviews. No API calls."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.llm.comparison import compare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, action='append', required=True,
                        help='已完成清理的報告，可重複指定 / cleaned report; repeat for each batch')
    args = parser.parse_args()
    try:
        result = compare(args.report)
    except Exception:
        parser.exit(1, '報告不完整、不相容或含重播；未接受比較。 / Incomplete, incompatible or replayed reports; comparison rejected.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
