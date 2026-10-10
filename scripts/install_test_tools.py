#!/usr/bin/env python3
"""驗證後安裝固定測試工具，不變更受測應用依賴。

Install verified pinned test tools without changing candidate runtime dependencies."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
from security_harness.preflight import verify, parse_lock
from security_harness.dependencies import scan
from security_harness.results import digest_file, write_json


def install():
    lock = ROOT / 'requirements-test.lock'
    policy = json.loads((ROOT / 'security/policy.json').read_text())
    policy['allowed_packages'] = ['hypothesis', 'ruff', 'sortedcontainers']
    if {r['name'] for r in parse_lock(lock)} != set(policy['allowed_packages']):
        raise ValueError('unexpected test tool inventory')
    provenance = verify(lock, policy)
    evidence = scan(lock)
    if evidence['findings']:
        raise ValueError('test tool vulnerability; installation refused')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PIP_', 'UV_'))}
    env['PIP_CONFIG_FILE'] = os.devnull
    python = str(ROOT / '.venv/bin/python')
    subprocess.run([python, '-m', 'pip', '--isolated', '--disable-pip-version-check', '--no-cache-dir',
                    'install', '--only-binary=:all:', '--no-deps', '--require-hashes',
                    '--index-url', 'https://pypi.org/simple', '-r', str(lock)],
                   env=env, check=True, timeout=180)
    subprocess.run([python, '-m', 'pip', 'check'], env=env, check=True, timeout=30)
    write_json(ROOT / 'artifacts/test-tools.json', {'lock_sha256': digest_file(lock),
               'provenance': provenance, 'dependency_evidence': evidence, 'installation': 'COMPLETE'})
    print('測試工具來源、冷卻期、雜湊與漏洞檢查通過 / Test tools verified and installed')


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        install()
    except Exception as exc:
        # 只記錄類型，不輸出可能含路徑或網址的例外文字。 / Record the type only, never exception text with paths or URLs.
        write_json(ROOT / 'artifacts/test-tools.json', {'installation': 'ERROR', 'error_type': type(exc).__name__})
        print(f'測試工具安裝失敗 / Test tool installation failed: {type(exc).__name__}')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
