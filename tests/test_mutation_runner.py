"""突變執行器不可把故障、空測試或取消當成攔截。

Mutation infrastructure must not count errors, empty runs or cancellation as kills."""
import ast
import os
from pathlib import Path
import shutil
import threading
import time

import pytest
from scripts.mutation_check import CAMPAIGN_SECONDS, MAX_MUTANTS, MAX_WORKERS, TARGETS, Workers, classify, missing_targets, mutations, run_tests


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
    # 先寫暫存檔再原子替換，逾時終止時不會留下空的 pid 檔。 / Write then atomically rename, so a timeout kill never leaves an empty pid file.
    (root / 'test_wait.py').write_text(f'import os,time\nfrom pathlib import Path\n'
                                       f'Path({str(pid) + ".tmp"!r}).write_text(str(os.getpid()))\n'
                                       f'os.replace({str(pid) + ".tmp"!r}, {str(pid)!r})\ntime.sleep(60)\n')
    before = time.monotonic()
    # 期限要留給隔離 pytest 啟動並寫出 pid；只給 2 秒時忙碌機器上 pid 檔可能還不存在。 / The deadline must leave room
    # for the isolated pytest to start and write its pid; with only 2 s the pid file may not exist on a busy machine.
    assert run_tests(root, ['test_wait.py'], root / 'run.log', 6) == ('TIMEOUT', 0)
    assert time.monotonic() - before < 20
    assert pid.exists(), 'the child never started before the deadline'
    child = int(pid.read_text())
    with pytest.raises(ProcessLookupError, match='No such process'):
        os.kill(child, 0)


def test_changed_case_identity_cannot_count_as_a_kill(tmp_path):
    xml = tmp_path / 'tests.xml'
    xml.write_text('<testsuite><testcase classname="other" name="a"><failure/></testcase></testsuite>')
    assert classify(1, xml, 1, {('test', 'a')}) == 'ERROR'
    xml.write_text('<testsuite><testcase classname="test" name="a"/><testcase classname="test" name="a"><failure/></testcase></testsuite>')
    assert classify(1, xml, 2) == 'ERROR'


def test_nested_same_column_boolean_nodes_are_mutated_independently():
    from scripts.mutation_check import mutations
    source = 'def target(a, b, c):\n    return a and b or c\n'
    produced = {identity: text for identity, text in mutations(source, ('target',))}
    bodies = sorted(text.split('return ', 1)[1].strip() for text in produced.values())
    # 外層 Or→And 與內層 And→Or 是兩個不同突變。 / Outer Or->And and inner And->Or are two distinct mutants.
    assert bodies == ['(a and b) and c', '(a or b) or c']


def test_mutation_worker_denies_process_launch_paths():
    from scripts.mutation_worker import DENIED_EVENTS
    assert {'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.fork', 'socket.connect'} <= DENIED_EVENTS


ROOT = Path(__file__).resolve().parents[1]


def test_every_mutation_target_resolves_and_a_renamed_one_is_reported():
    # 函式改名後，它的突變原本會靜默消失。 / A renamed function used to drop its mutants silently.
    for path, (functions, _) in TARGETS.items():
        assert missing_targets((ROOT / path).read_text(encoding='utf-8'), functions) == [], path
    source = 'def present(a, b):\n    return a == b\n\n\nclass Gate:\n    def check(self, a):\n        return a\n'
    assert missing_targets(source, ('present', 'Gate.check')) == []
    assert missing_targets(source, ('present', 'renamed_away', 'Gate.gone')) == ['Gate.gone', 'renamed_away']


def test_mutation_guide_lists_every_target_and_the_mutant_cap():
    # 目標清單與上限在文件中英兩段手抄；增刪目標時漏改文件會直接失敗。 / The target list and cap are copied by hand into
    # both language sections of the guide; adding or removing a target without the guide now fails.
    guide = (ROOT / 'docs/mutation-testing.zh-TW.md').read_text(encoding='utf-8')
    chinese, english = guide.split('<a id="en"></a>', 1)
    for path in TARGETS:
        assert f'`{path}`' in chinese, path
        assert Path(path).name in english, path
    assert f'超過 {MAX_MUTANTS} 個突變' in chinese
    assert f'more-than-{MAX_MUTANTS}' in english
    assert CAMPAIGN_SECONDS % 60 == 0
    assert f'整批上限 {CAMPAIGN_SECONDS // 60} 分鐘' in chinese
    assert f'Campaign deadline is {CAMPAIGN_SECONDS // 60} minutes.' in english
    assert f'最多 {MAX_WORKERS} 個 worker 平行處理' in chinese
    assert f'spread over up to {MAX_WORKERS} workers' in english


def worker_snapshots(tmp_path, count):
    """每個快照放在自己的上層目錄，與突變活動相同。 / Each snapshot sits in its own parent, as in the campaign."""
    snapshots = []
    for index in range(count):
        root = worker_root(tmp_path / f'w{index}')
        (root / 'target.py').write_text('def value():\n    return 1\n')
        (root / 'test_target.py').write_text('from target import value\n\n\ndef test_value():\n    assert value() == 1\n')
        snapshots.append(root)
    return snapshots


def test_parallel_workers_keep_mutant_order_and_restore_every_snapshot(tmp_path):
    snapshots = worker_snapshots(tmp_path, 2)
    mutants = [(f'm{i}', f'def value():\n    return {v}\n') for i, v in enumerate((2, 1, 3, 1, 4))]
    statuses = Workers(snapshots).run('target.py', mutants, ['test_target.py'], 1, {('test_target', 'test_value')},
                                      time.monotonic() + 120)
    assert statuses == ['KILLED', 'SURVIVED', 'KILLED', 'SURVIVED', 'KILLED']
    for root in snapshots:
        assert (root / 'target.py').read_text() == 'def value():\n    return 1\n'


def test_cancelling_parallel_workers_reaps_running_children_and_fails(tmp_path):
    # 取消不得被當成攔截或完成；執行中的子程序群組須被終止。 / Cancellation is never a kill or a completed campaign,
    # and running child process groups must be terminated.
    snapshots = worker_snapshots(tmp_path, 2)
    slow = 'import time\n\n\ndef value():\n    time.sleep(60)\n    return 1\n'
    workers = Workers(snapshots)
    outcome = {}

    def campaign():
        try:
            workers.run('target.py', [('a', slow), ('b', slow)], ['test_target.py'], 1,
                        {('test_target', 'test_value')}, time.monotonic() + 120)
        except BaseException as error:
            outcome['error'] = error

    thread = threading.Thread(target=campaign)
    before = time.monotonic()
    thread.start()
    while len(workers.active) < 2 and time.monotonic() - before < 20:
        time.sleep(0.05)
    children = [process.pid for process in workers.active]
    assert len(children) == 2
    workers.cancel()
    thread.join(20)
    assert not thread.is_alive() and time.monotonic() - before < 30
    assert isinstance(outcome.get('error'), RuntimeError)
    for child in children:
        with pytest.raises(ProcessLookupError):
            os.kill(child, 0)
    for root in snapshots:
        assert (root / 'target.py').read_text() == 'def value():\n    return 1\n'
