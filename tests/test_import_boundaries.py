"""命名空間遮蔽與匯入副作用回歸；Namespace shadowing and import-side-effect regressions."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('package', ['scripts', 'tests'])
def test_foreign_regular_package_cannot_replace_repository_package(tmp_path, package):
    foreign = tmp_path / package
    foreign.mkdir()
    (foreign / '__init__.py').write_text('raise RuntimeError("foreign namespace executed")\n')
    code = ('import sys,importlib,json;sys.path[:0]=sys.argv[1:3];'
            'p=importlib.import_module(sys.argv[3]);print(json.dumps(p.__file__))')
    result = subprocess.run([sys.executable, '-I', '-c', code, str(ROOT), str(tmp_path), package],
                            capture_output=True, text=True, timeout=10, check=True)
    assert Path(json.loads(result.stdout)) == ROOT / package / '__init__.py'


def test_importing_cli_modules_does_not_mutate_global_search_path():
    code = '''import sys,importlib
sys.path.insert(0,sys.argv[1])
before=list(sys.path)
for name in ('model_smoke','model_review','model_compare','model_worker','cleanup_runs',
             'check_trusted_changes','audit_merge_protection','run_security','prepare_publisher_deployment'):
    module=importlib.import_module('scripts.'+name)
    importlib.reload(module)
assert sys.path == before
'''
    subprocess.run([sys.executable, '-I', '-c', code, str(ROOT)], capture_output=True,
                   text=True, timeout=10, check=True)


def test_test_helpers_have_one_canonical_module_identity():
    import tests.test_model_benchmark as package_module
    assert sys.modules['tests.test_model_benchmark'] is package_module
    assert 'test_model_benchmark' not in sys.modules


@pytest.mark.parametrize('script', ['model_smoke.py', 'model_review.py', 'model_compare.py', 'run_security.py'])
def test_isolated_cli_ignores_candidate_cwd_and_pythonpath(tmp_path, script):
    marker = tmp_path / 'unexpected-import'
    for package in ('scripts', 'security_harness'):
        p = tmp_path / package
        p.mkdir()
        (p / '__init__.py').write_text('raise RuntimeError("candidate namespace imported")\n')
    (tmp_path / 'json.py').write_text(f'open({str(marker)!r},"w").write("unexpected")\n')
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'LANG', 'SYSTEMROOT')}
    env['PYTHONPATH'] = str(tmp_path)
    result = subprocess.run([sys.executable, '-I', str(ROOT / 'scripts' / script), '--help'],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert 'usage:' in result.stdout


@pytest.mark.parametrize('changed', ['scripts/__init__.py', 'security_harness/__init__.py',
    'security_harness/inputs.py', 'security_harness/limits.py', 'security_harness/candidate_git.py',
    'scripts/model_review.py', 'scripts/model_compare.py', 'requirements.lock'])
def test_model_digest_binds_package_and_transitive_core_changes(tmp_path, monkeypatch, changed):
    import shutil
    from scripts import model_smoke
    paths = {ROOT / 'scripts/__init__.py', ROOT / 'security_harness/__init__.py',
             ROOT / 'requirements.lock', ROOT / 'security/model-roe.json',
             *ROOT.glob('scripts/model_*.py'), *ROOT.glob('security_harness/**/*.py')}
    for path in paths:
        target = tmp_path / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    monkeypatch.setattr(model_smoke, 'ROOT', tmp_path)
    before = model_smoke.implementation_digest()
    target = tmp_path / changed
    target.write_bytes(target.read_bytes() + b'\n# synthetic revision marker\n')
    assert model_smoke.implementation_digest() != before
