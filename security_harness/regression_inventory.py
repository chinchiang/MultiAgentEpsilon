"""以語法樹靜態列出回歸測試與其案例數，不匯入、不執行任何測試程式碼。

Statically list regression tests and their case counts from syntax trees,
without importing or running any test code. A parametrize decorator whose
values are a literal list or tuple counts its length; any other form counts
one, so the totals are a lower bound that cannot be inflated by code."""
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


def file_tests(name, tree):
    tests = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'):
            tests[f'{name}::{node.name}'] = case_count(node)
        elif isinstance(node, ast.ClassDef) and node.name.startswith('Test'):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith('test_'):
                    tests[f'{name}::{node.name}::{item.name}'] = case_count(item)
    return tests


def inventory(root, paths):
    """root 底下列出的測試檔中每個測試的靜態案例數；無法解析的檔案略過（文件檢查另行報錯）。

Static case count of every test in the listed test files under root. Unparsable
    files are skipped here; the documentation check reports them separately."""
    tests = {}
    for name in sorted(p for p in paths if is_test_file(p)):
        try:
            tree = ast.parse(Path(root, name).read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
            continue
        tests.update(file_tests(name, tree))
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


def floor_errors(base, candidate, declared):
    """base 中消失或案例數減少、且未在候選明列的測試。 / Tests that disappeared from base or lost cases and
    are not declared by the candidate."""
    errors = []
    for test, count in sorted(base.items()):
        now = candidate.get(test, 0)
        if now < count and test not in declared:
            errors.append(f'{test}: regression test removed or reduced ({count} → {now}) without an entry in '
                          f'{REMOVED_TESTS} / 回歸測試被刪除或減少，未在 {REMOVED_TESTS} 列出')
    return errors
