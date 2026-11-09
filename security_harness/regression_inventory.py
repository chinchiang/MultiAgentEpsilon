"""以語法樹靜態列出回歸測試與其案例數，不匯入、不執行任何測試程式碼。

Statically list regression tests and their case counts from syntax trees,
without importing or running any test code. A parametrize decorator whose
values are a literal list or tuple counts its length; any other form counts
one, so the totals are a lower bound that cannot be inflated by code. Each test
also has a static check count: its assert statements plus pytest.raises,
pytest.warns and pytest.fail calls, so a test kept by name but stripped of its
checks is caught too."""
import ast
import json
from pathlib import Path, PurePosixPath

REMOVED_TESTS = 'security/removed-tests.json'


def is_test_file(name):
    path = PurePosixPath(name)
    return path.parts[:1] == ('tests',) and path.name.startswith('test_') and path.suffix == '.py'


def parametrize_cases(decorator):
    """單一 decorator 帶來的案例倍數。 / The case multiplier one decorator contributes."""
    if not isinstance(decorator, ast.Call):
        return 1
    target = decorator.func
    if not (isinstance(target, ast.Attribute) and target.attr == 'parametrize'):
        return 1
    values = decorator.args[1] if len(decorator.args) > 1 else next(
        (k.value for k in decorator.keywords if k.arg == 'argvalues'), None)
    if isinstance(values, (ast.List, ast.Tuple)):
        return max(len(values.elts), 1)
    return 1


def case_count(function):
    count = 1
    for decorator in function.decorator_list:
        count *= parametrize_cases(decorator)
    return count


# 計入檢查數的 pytest 呼叫。 / The pytest calls that count as checks.
CHECK_CALLS = frozenset({'raises', 'warns', 'fail'})


def check_count(function):
    """測試本體中的 assert 與 pytest.raises／warns／fail 呼叫數。 / The asserts and pytest.raises, warns and fail calls in
    a test's body."""
    count = 0
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            count += 1
        elif isinstance(node, ast.Call):
            target = node.func
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, 'id', None)
            count += name in CHECK_CALLS
    return count


def named_tests(name, tree):
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'):
            yield f'{name}::{node.name}', node
        elif isinstance(node, ast.ClassDef) and node.name.startswith('Test'):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith('test_'):
                    yield f'{name}::{node.name}::{item.name}', item


def file_tests(name, tree, measure=case_count):
    return {test: measure(node) for test, node in named_tests(name, tree)}


def inventory(root, paths, measure=case_count):
    """root 底下列出的測試檔中每個測試的靜態案例數（或以 measure 量測的其他數值）；無法解析的檔案略過（文件檢查另行報錯）。

Static case count of every test in the listed test files under root, or another
    figure taken by measure. Unparsable files are skipped here; the documentation
    check reports them separately."""
    tests = {}
    for name in sorted(p for p in paths if is_test_file(p)):
        try:
            tree = ast.parse(Path(root, name).read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
            continue
        tests.update(file_tests(name, tree, measure))
    return tests


def declared_removals(root):
    """候選在 security/removed-tests.json 明列的移除，理由必填。 / Removals the candidate declares in
    security/removed-tests.json; every entry needs a reason."""
    path = Path(root, REMOVED_TESTS)
    if not path.is_file():
        return {}, []
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}, [f'{REMOVED_TESTS}: unreadable / 無法讀取']
    if not isinstance(data, list) or not all(
            isinstance(e, dict) and set(e) == {'test', 'reason'} and isinstance(e['test'], str)
            and isinstance(e['reason'], str) and e['reason'].strip() for e in data):
        return {}, [f'{REMOVED_TESTS}: each entry needs "test" and a non-empty "reason" / 每筆須有 test 與理由']
    return {e['test']: e['reason'] for e in data}, []


def floor_errors(base, candidate, declared, base_checks=None, candidate_checks=None):
    """base 中消失、案例數或檢查數減少，且未在候選明列的測試；以及列給未被削減的 base 測試的過期宣告。

Tests that disappeared from base or lost cases or checks and are not declared by the
    candidate, and stale declarations that name a base test the candidate did not reduce."""
    base_checks, candidate_checks = base_checks or {}, candidate_checks or {}
    errors = []
    for test, count in sorted(base.items()):
        now = candidate.get(test, 0)
        if now < count and test not in declared:
            errors.append(f'{test}: regression test removed or reduced ({count} → {now}) without an entry in '
                          f'{REMOVED_TESTS} / 回歸測試被刪除或減少，未在 {REMOVED_TESTS} 列出')
        elif now >= count and test in candidate:
            had, has = base_checks.get(test, 0), candidate_checks.get(test, 0)
            if has < had and test not in declared:
                errors.append(f'{test}: regression test lost checks ({had} → {has}) without an entry in '
                              f'{REMOVED_TESTS} / 回歸測試的斷言減少，未在 {REMOVED_TESTS} 列出')
            elif has >= had and test in declared:
                # 宣告只能說明實際的削減；列給完好的測試等於預先放行日後弱化。 / A declaration may only explain an actual
                # reduction; naming an intact test would pre-authorize weakening it later.
                errors.append(f'{test}: stale entry in {REMOVED_TESTS}; the test was not reduced / '
                              f'{REMOVED_TESTS} 的過期項目：該測試未被削減')
    return errors
