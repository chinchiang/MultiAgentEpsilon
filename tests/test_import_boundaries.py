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


DIGEST_BOUND = ['scripts/__init__.py', 'security_harness/__init__.py', 'security_harness/inputs.py',
                'security_harness/limits.py', 'security_harness/candidate_git.py', 'security_harness/llm/config.py',
                'scripts/model_review.py', 'scripts/model_compare.py', 'requirements.lock', 'security/model-roe.json',
                # 模型套件直接或間接匯入的共用模組，含函式內延後匯入的。 / Shared modules the model package imports
                # directly or transitively, including those imported inside a function.
                'security_harness/scope.py', 'security_harness/supervision.py', 'security_harness/results.py',
                'security_harness/dependencies.py', 'security_harness/preflight.py',
                'security_harness/llm/benchmark_score.py', 'scripts/model_worker.py']
# 模型評測從不匯入的模組：改動它們不得讓既有報告變成無法比較。 / Modules the model benchmark never imports: changing
# them must not make existing reports incomparable.
DIGEST_UNBOUND = ['security_harness/authorization.py', 'security_harness/github_trust.py',
                  'security_harness/trusted_publisher.py', 'security_harness/isolation.py',
                  'security_harness/secrets.py', 'security_harness/workflow_contract.py']


def digest_tree(tmp_path, monkeypatch):
    import shutil
    from security_harness.llm import config
    # 複製整個來源樹，而非重用摘要本身的挑選公式。 / Copy whole trees instead of reusing the digest's own selection formula.
    for folder in ('scripts', 'security_harness', 'security', 'docs'):
        shutil.copytree(ROOT / folder, tmp_path / folder, ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copyfile(ROOT / 'requirements.lock', tmp_path / 'requirements.lock')
    monkeypatch.setattr(config, 'ROOT', tmp_path)
    return config


@pytest.mark.parametrize('changed', DIGEST_BOUND)
def test_model_digest_binds_package_and_transitive_core_changes(tmp_path, monkeypatch, changed):
    config = digest_tree(tmp_path, monkeypatch)
    before = config.implementation_digest()
    target = tmp_path / changed
    target.write_bytes(target.read_bytes() + b'\n# synthetic revision marker\n')
    assert config.implementation_digest() != before


@pytest.mark.parametrize('unrelated', ['scripts/dev_db.py', 'security/policy.json', 'docs/lmstudio.zh-TW.md'])
def test_model_digest_ignores_unrelated_files(tmp_path, monkeypatch, unrelated):
    config = digest_tree(tmp_path, monkeypatch)
    before = config.implementation_digest()
    target = tmp_path / unrelated
    target.write_bytes(target.read_bytes() + b'\n')
    assert config.implementation_digest() == before


WORKERS = {'isolation_worker.py', 'model_process.py', 'model_worker.py', 'mutation_worker.py', 'security_worker.py',
           '__init__.py'}


@pytest.mark.parametrize('script', sorted(p.name for p in (ROOT / 'scripts').glob('*.py') if p.name not in WORKERS))
def test_every_entry_point_help_is_side_effect_free(tmp_path, script):
    # --help 只能列印說明：不得執行管線、清理、安裝或網路動作。 / --help only prints usage: no pipeline, cleanup,
    # installation or network action may start.
    latest = ROOT / 'artifacts/latest.txt'
    before = latest.read_text() if latest.exists() else None
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'LANG', 'SYSTEMROOT')}
    result = subprocess.run([sys.executable, '-I', str(ROOT / 'scripts' / script), '--help'],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith('usage:')
    assert (latest.read_text() if latest.exists() else None) == before


def test_worker_entry_points_are_explicitly_listed():
    assert WORKERS - {'__init__.py'} == {p.name for p in (ROOT / 'scripts').glob('*_worker.py')} | {'model_process.py'}


def test_ci_provenance_outside_actions_fails_with_a_message(tmp_path):
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'LANG')}
    result = subprocess.run([sys.executable, '-I', str(ROOT / 'scripts/write_ci_provenance.py')],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 2 and 'GITHUB_REPOSITORY' in result.stderr and 'Traceback' not in result.stderr


def test_every_cli_argument_has_bilingual_help():
    import ast
    import re
    missing = []
    for path in sorted((ROOT / 'scripts').glob('*.py')):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'add_argument':
                text = next((k.value.value for k in node.keywords if k.arg == 'help'
                             and isinstance(k.value, ast.Constant)), '')
                if not (re.search('[一-鿿]', text) and re.search('[A-Za-z]{3,}', text)):
                    missing.append(f'{path.name}:{node.lineno}')
    assert missing == []


@pytest.mark.parametrize('unrelated', DIGEST_UNBOUND)
def test_model_digest_ignores_harness_modules_the_benchmark_never_imports(tmp_path, monkeypatch, unrelated):
    """與模型評測無關的 security_harness 模組不在實作摘要內，改動它們不影響跨報告比較。

    Harness modules unrelated to the model benchmark are outside the implementation digest, so changing them leaves
    reports comparable."""
    config = digest_tree(tmp_path, monkeypatch)
    before = config.implementation_digest()
    target = tmp_path / unrelated
    target.write_bytes(target.read_bytes() + b'\n# synthetic revision marker\n')
    assert config.implementation_digest() == before


def test_model_digest_follows_a_newly_imported_shared_module(tmp_path, monkeypatch):
    """摘要範圍由匯入關係決定：模型套件新匯入一個共用模組（即使寫在函式內），該模組就進入摘要。

    The digest scope follows the imports: once the model package imports another shared module, even inside a
    function, that module is bound."""
    config = digest_tree(tmp_path, monkeypatch)
    module = tmp_path / 'security_harness/workflow_contract.py'
    assert module not in config.implementation_files()
    gateway = tmp_path / 'security_harness/llm/gateway.py'
    gateway.write_bytes(gateway.read_bytes() + b'\n\ndef late():\n    from .. import workflow_contract\n'
                        b'    return workflow_contract\n')
    assert module in config.implementation_files()
    before = config.implementation_digest()
    module.write_bytes(module.read_bytes() + b'\n# synthetic revision marker\n')
    assert config.implementation_digest() != before


def test_model_digest_scope_matches_what_the_benchmark_loads_at_run_time():
    """靜態匯入範圍不得小於實際載入的模組：在乾淨的直譯器匯入模型入口後，已載入的本專案模組都在摘要範圍內。

    The static scope is never smaller than what really loads: after a clean interpreter imports the model entry
    points, every loaded project module is inside the digest scope."""
    code = ("import sys, json\n"
            "from scripts import model_review, model_compare, model_smoke, model_worker, model_process\n"
            "from security_harness.llm import config, comparison, benchmark_runner, lifecycle\n"
            "loaded = {m.__file__ for n, m in sys.modules.items() if n.split('.')[0] in ('scripts', 'security_harness')"
            " and getattr(m, '__file__', None)}\n"
            "bound = {str(p) for p in config.implementation_files()}\n"
            "print(json.dumps(sorted(loaded - bound)))\n")
    result = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []

