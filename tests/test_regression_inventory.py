"""候選測試數下限的純函式測試；不呼叫 git，可供突變測試使用。 / Pure-function tests of the candidate test floor; they never
call git, so mutation testing can use them."""
import ast
import json

import pytest

from security_harness import regression_inventory as inventory

SOURCE = '''
import pytest

@pytest.mark.parametrize("x", [1, 2, 3])
@pytest.mark.parametrize("y", (4, 5))
def test_grid(x, y):
    assert x
    assert y

@pytest.mark.parametrize("x", range(9))
def test_dynamic(x):
    with pytest.raises(ValueError):
        int("x")
    pytest.warns(UserWarning)
    pytest.fail("never")

@pytest.mark.parametrize(argnames="x", argvalues=[1, 2])
def test_keyword(x):
    pass

@pytest.mark.parametrize("x", [])
def test_empty(x):
    raises = 1
    assert raises

class TestGroup:
    def test_inside(self):
        assert True

    def helper(self):
        assert False

def helper():
    assert False
'''


def measured(measure):
    return inventory.file_tests('tests/test_x.py', ast.parse(SOURCE), measure)


def test_case_counts_multiply_literal_parameters_and_count_the_rest_once():
    assert measured(inventory.case_count) == {
        'tests/test_x.py::test_grid': 6, 'tests/test_x.py::test_dynamic': 1, 'tests/test_x.py::test_keyword': 2,
        'tests/test_x.py::test_empty': 1, 'tests/test_x.py::TestGroup::test_inside': 1}


def test_check_counts_asserts_and_pytest_raises_warns_and_fail():
    assert measured(inventory.check_count) == {
        'tests/test_x.py::test_grid': 2, 'tests/test_x.py::test_dynamic': 3, 'tests/test_x.py::test_keyword': 0,
        'tests/test_x.py::test_empty': 1, 'tests/test_x.py::TestGroup::test_inside': 1}


@pytest.mark.parametrize('name,expected', [('tests/test_a.py', True), ('tests/sub/test_a.py', True),
                                           ('tests/a_test.py', False), ('tests/test_a.txt', False),
                                           ('other/test_a.py', False)])
def test_only_test_modules_under_tests_are_counted(name, expected):
    assert inventory.is_test_file(name) is expected


def test_inventory_skips_unparsable_files(tmp_path):
    (tmp_path / 'tests').mkdir()
    (tmp_path / 'tests/test_ok.py').write_text('def test_a():\n    assert 1\n')
    (tmp_path / 'tests/test_bad.py').write_text('def (:\n')
    paths = ['tests/test_ok.py', 'tests/test_bad.py', 'README.md']
    assert inventory.inventory(tmp_path, paths) == {'tests/test_ok.py::test_a': 1}
    assert inventory.inventory(tmp_path, paths, inventory.check_count) == {'tests/test_ok.py::test_a': 1}


BASE = {'t::kept': 2, 't::gone': 1, 't::checked': 1}
CHECKS = {'t::kept': 3, 't::gone': 1, 't::checked': 2}


def errors(candidate, checks, declared=()):
    return inventory.floor_errors(BASE, candidate, {d: 'reason' for d in declared}, CHECKS, checks)


def test_intact_or_grown_tests_pass():
    assert errors({**BASE, 't::new': 1}, {**CHECKS, 't::kept': 4}) == []


def test_removed_reduced_or_weakened_tests_block_unless_declared():
    found = errors({'t::kept': 1, 't::checked': 1}, {'t::kept': 3, 't::checked': 1})
    assert [e.split(':')[0] + ':' + e.split(':')[2] for e in found] == ['t:checked', 't:gone', 't:kept']
    assert '(2 → 1)' in found[2] and '(1 → 0)' in found[1] and 'lost checks (2 → 1)' in found[0]
    assert errors({'t::kept': 1, 't::checked': 1}, {'t::kept': 3, 't::checked': 1},
                  ('t::kept', 't::gone', 't::checked')) == []


def test_declaration_for_an_intact_base_test_is_stale_but_one_for_a_missing_base_test_is_not():
    found = errors(dict(BASE), dict(CHECKS), ('t::checked', 't::long-gone'))
    assert len(found) == 1 and found[0].startswith('t::checked: stale entry')


def test_floor_without_check_counts_still_compares_cases():
    assert inventory.floor_errors(BASE, BASE, {}) == []
    assert len(inventory.floor_errors(BASE, {}, {})) == 3


@pytest.mark.parametrize('content,valid', [
    ([{'test': 't::a', 'reason': 'why'}], True),
    ([{'test': 't::a', 'reason': ' '}], False),
    ([{'test': 't::a'}], False),
    ([{'test': 't::a', 'reason': 'why', 'extra': 1}], False),
    ([{'test': 1, 'reason': 'why'}], False),
    ({'test': 't::a', 'reason': 'why'}, False),
])
def test_declarations_need_a_test_and_a_reason(tmp_path, content, valid):
    (tmp_path / 'security').mkdir()
    (tmp_path / inventory.REMOVED_TESTS).write_text(json.dumps(content))
    declared, problems = inventory.declared_removals(tmp_path)
    assert (declared == {'t::a': 'why'} and problems == []) is valid
    assert bool(problems) is not valid


def test_missing_or_unreadable_declarations(tmp_path):
    assert inventory.declared_removals(tmp_path) == ({}, [])
    (tmp_path / 'security').mkdir()
    (tmp_path / inventory.REMOVED_TESTS).write_text('not json')
    assert inventory.declared_removals(tmp_path)[1] == [f'{inventory.REMOVED_TESTS}: unreadable / 無法讀取']
