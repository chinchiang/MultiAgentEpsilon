"""突變執行器不可把故障、空測試或取消當成攔截。

Mutation infrastructure must not count errors, empty runs or cancellation as kills."""
import ast
import os
from pathlib import Path
import shutil
import sys
import time

import pytest
from scripts.mutation_check import mutations, classify, run_tests


@pytest.mark.parametrize('xml,code,expected', [
    ('<testsuite><testcase classname="test" name="a"/></testsuite>', 0, 'SURVIVED'),
    ('<testsuite><testcase classname="test" name="a"><failure/></testcase></testsuite>', 1, 'KILLED'),
    ('<testsuite><testcase classname="test" name="a"><error/></testcase></testsuite>', 1, 'ERROR'),
    ('<testsuite><testcase classname="test" name="a"><skipped/></testcase></testsuite>', 0, 'ERROR'),
    ('<testsuite/>', 0, 'ERROR'),
    ('<testsuite><testcase/><testcase classname="test" name="a"><failure/></testcase></testsuite>', 1, 'ERROR'),
    ('<testsuite><testcase classname="test" name="a"><failure/></testcase></testsuite>', 2, 'ERROR'),
    ('broken', 1, 'ERROR'),
])
def test_test_outcome_contract(xml, code, expected, tmp_path):
    path = tmp_path / 'tests.xml'; path.write_text(xml)
    assert classify(code, path, 1) == expected


def test_missing_junit_is_an_error(tmp_path):
    assert classify(1, tmp_path / 'missing.xml', 1) == 'ERROR'


def test_mutations_are_deterministic_and_change_only_selected_function():
    source = 'def target(x):\n    return x > 0 and not x == 2\ndef untouched(x):\n    return x > 3\n'
    changed = mutations(source, ('target',))
    assert changed == mutations(source, ('target',))
    assert len(changed) == 4 and len({n for n, _ in changed}) == 4
    original = {}; exec(source, original)
    for _, text in changed:
        ast.parse(text)
        namespace = {}; exec(text, namespace)
        assert any(namespace['target'](x) != original['target'](x) for x in (0, 1, 2, 3))
        assert all(namespace['untouched'](x) == original['untouched'](x) for x in (0, 1, 2, 3, 4))


def worker_root(tmp_path):
    root = tmp_path / 'source'; (root / 'scripts').mkdir(parents=True)
    worker = Path(__file__).resolve().parents[1] / 'scripts/mutation_worker.py'
    shutil.copyfile(worker, root / 'scripts/mutation_worker.py')
    return root


def test_worker_has_no_inherited_keys_and_blocks_network_and_processes(tmp_path, monkeypatch):
    root = worker_root(tmp_path)
    monkeypatch.setenv('GEMINI_API_KEY', 'synthetic-secret')
    (root / 'test_guard.py').write_text('''import os, socket, subprocess
import pytest
def test_guard():
    assert 'GEMINI_API_KEY' not in os.environ
    with pytest.raises(RuntimeError):
        socket.getaddrinfo('example.invalid',443)
    with pytest.raises(RuntimeError):
        subprocess.run(['/bin/true'])
''')
    assert run_tests(root, ['test_guard.py'], root / 'run.log', 10) == (0, 1)


def test_timeout_is_separate_from_killed_and_child_is_reaped(tmp_path):
    root = worker_root(tmp_path)
    pid = tmp_path / 'child.pid'
    (root / 'test_wait.py').write_text(f'import os,time\nfrom pathlib import Path\nPath({str(pid)!r}).write_text(str(os.getpid()))\ntime.sleep(60)\n')
    before = time.monotonic()
    assert run_tests(root, ['test_wait.py'], root / 'run.log', 2) == ('TIMEOUT', 0)
    assert time.monotonic() - before < 10
    child = int(pid.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_changed_case_identity_cannot_count_as_a_kill(tmp_path):
    xml = tmp_path / 'tests.xml'
    xml.write_text('<testsuite><testcase classname="other" name="a"><failure/></testcase></testsuite>')
    assert classify(1, xml, 1, {('test', 'a')}) == 'ERROR'
    xml.write_text('<testsuite><testcase classname="test" name="a"/><testcase classname="test" name="a"><failure/></testcase></testsuite>')
    assert classify(1, xml, 2) == 'ERROR'
