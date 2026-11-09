"""規則集範本與種子資料的一致性；只讀檔案與語法樹，不匯入候選應用。 / Consistency of the ruleset template and the
seed data; reads files and syntax trees only, never importing the candidate application."""
import ast
import json
from pathlib import Path

import pytest

from scripts.audit_merge_protection import inspect_configuration

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'docs/github-main-ruleset.json'


def template():
    return json.loads(TEMPLATE.read_text())


def evaluate(ruleset):
    pr = {'user': {'login': 'author'}}
    collaborators = [{'login': 'reviewer', 'role_name': 'write'}]
    return inspect_configuration({'protected': True}, [ruleset], pr, collaborators, ['reviewer'],
                                 codeowners='* @reviewer\n')['configuration']


REQUIRED = ('main_protected', 'active_main_ruleset', 'no_bypass', 'no_delete_or_force_push',
            'independent_review_required', 'merge_commit_only', 'review_thread_resolution_required',
            'unattributed_changes_extra_approval', 'required_check_present', 'strict_checks')


def test_the_ruleset_template_meets_every_protection_the_audit_requires():
    # 範本先前沒有任何測試；稽核要求的每一項都必須由範本本身滿足。 / The template had no test; it must itself meet every
    # protection the audit requires.
    configuration = evaluate(template())
    assert {name: configuration[name] for name in REQUIRED} == dict.fromkeys(REQUIRED, True)


def test_the_template_keeps_the_last_push_approval_the_guard_depends_on():
    rules = [r for r in template()['rules'] if r['type'] == 'pull_request']
    assert len(rules) == 1 and rules[0]['parameters']['require_last_push_approval'] is True


@pytest.mark.parametrize('weaken,flag', [
    (lambda r: r['bypass_actors'].append({'actor_id': 1}), 'no_bypass'),
    (lambda r: r['rules'][2]['parameters']['allowed_merge_methods'].append('squash'), 'merge_commit_only'),
    (lambda r: r['rules'][2]['parameters'].update(require_last_push_approval=False), 'independent_review_required'),
    (lambda r: r['rules'][3]['parameters']['required_status_checks'][0].update(integration_id=1), 'required_check_present'),
    (lambda r: r['rules'][3]['parameters'].update(strict_required_status_checks_policy=False), 'strict_checks'),
], ids=['bypass', 'squash', 'last-push', 'check-source', 'not-strict'])
def test_weakening_the_template_is_caught(weaken, flag):
    ruleset = template()
    weaken(ruleset)
    assert evaluate(ruleset)[flag] is False


def functions(path, *names):
    tree = ast.parse((ROOT / path).read_text(encoding='utf-8'))
    found = {node.name: ast.dump(node) for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names}
    assert set(found) == set(names), path
    return found


def test_oracle_and_candidate_seed_the_same_synthetic_data():
    # 可信 oracle 不可匯入候選應用，因此種子資料各寫一份；兩份必須逐字一致，否則 oracle 與應用會各看一套資料。 / The
    # trusted oracle must not import the candidate application, so the seed is written twice; the two must match
    # exactly, or the oracle and the application would see different data.
    names = ('seed', 'password_hash')
    assert functions('security_harness/fixture_database.py', *names) == functions('fixture_app/app.py', *names)
