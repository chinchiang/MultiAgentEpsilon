#!/usr/bin/env python3
"""排程監看：線上 main 規則集一旦弱於稽核要求就失敗。只讀 GitHub，不需要 PR，也不宣稱行為驗收。

Scheduled monitor: fail as soon as the live main ruleset is weaker than the audit requires.
Read-only, needs no pull request and certifies no behavioral probe."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from scripts.audit_merge_protection import ruleset_protections
from security_harness.github_readonly import GitHubReader, ReadOnlyGitHub
from security_harness.results import write_json


def assess(branch, rulesets):
    """每一項保護都成立才是 OK。bypass 名單讀不到（權杖沒有規則集管理權限）時列為 unknown，不算漂移；讀得到且非空，或沒有
    生效的規則集，才算漂移。

Every protection must hold for OK. A bypass list the token cannot read (no ruleset administration access) is
    reported as unknown, not as drift; a readable non-empty list, or no active ruleset, is drift."""
    protections, active, _, _ = ruleset_protections(branch, rulesets)
    failed = sorted(name for name, held in protections.items() if not held)
    unknown = []
    bypass = [r.get('bypass_actors') for r in active]
    if ('no_bypass' in failed and any(not isinstance(b, list) for b in bypass)
            and not any(isinstance(b, list) and b for b in bypass)):
        failed.remove('no_bypass')
        unknown.append('no_bypass')
    return {'decision': 'DRIFT' if failed else 'OK', 'failed': failed, 'unknown': unknown,
            'protections': protections,
            'rulesets': [{'id': r.get('id'), 'name': r.get('name'), 'updated_at': r.get('updated_at')} for r in active]}


def monitor(reader):
    """讀取失敗一律回報 ERROR：監看不到不等於沒問題。 / A failed read reports ERROR: not seeing is not the same as fine."""
    try:
        branch = reader.get('branches/main')
        rulesets = [reader.get('rulesets/' + str(r['id'])) for r in reader.items('rulesets?includes_parents=true')]
        evidence = assess(branch, rulesets)
        evidence.update(repository=reader.repository, main_sha=branch['commit']['sha'])
    except Exception as exc:
        evidence = {'decision': 'ERROR', 'failed': [], 'unknown': [], 'errors': [type(exc).__name__]}
    return evidence


def main(argv=None, reader=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/ruleset-monitor.json',
                        help='監看證據路徑 / monitor evidence path')
    args = parser.parse_args(argv)
    if reader is None:
        repository = json.loads((ROOT / 'security/trust-policy.json').read_text())['repository']
        reader = GitHubReader(ReadOnlyGitHub(), repository)
    evidence = monitor(reader)
    write_json(args.output, evidence)
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    for name in evidence['unknown']:
        # GitHub Actions 會把這一行顯示成警告註記。 / GitHub Actions renders this line as a warning annotation.
        print(f"::warning::{name} is unknown: this token cannot read the ruleset bypass list")
    return 0 if evidence['decision'] == 'OK' else 1


if __name__ == '__main__':
    raise SystemExit(main())
