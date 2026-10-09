from scripts.audit_merge_protection import inspect_configuration
import pytest


def test_empty_rules_and_author_only_never_claim_remote_acceptance():
    result = inspect_configuration({'protected': False}, [], {'user': {'login': 'author'}},
                                   [{'login': 'author', 'role_name': 'admin'}], ['author'])
    assert result['decision'] == 'BLOCK'
    assert not result['acceptance_complete']
    assert not any(result['configuration'].values())
    assert set(result['behavioral_probes'].values()) == {'NOT_RUN'}


def test_active_unrelated_branch_rules_do_not_protect_main():
    unrelated = {'enforcement': 'active', 'target': 'branch',
                 'conditions': {'ref_name': {'include': ['refs/heads/sandbox'], 'exclude': []}},
                 'bypass_actors': [], 'rules': [{'type': 'deletion'}, {'type': 'non_fast_forward'}]}
    result = inspect_configuration({'protected': False}, [unrelated], {'user': {'login': 'author'}}, [], [])
    assert not result['configuration']['active_main_ruleset']
    assert not result['configuration']['no_delete_or_force_push']


@pytest.mark.parametrize('role,available', [('read', False), ('triage', False),
                                          ('write', True), ('maintain', True), ('admin', True),
                                          (None, False), ('custom-unverified', False)])
def test_independent_reviewer_requires_verified_write_capable_role(role, available):
    result = inspect_configuration({'protected': False}, [], {'user': {'login': 'author'}},
                                   [{'login': 'reviewer', 'role_name': role}], ['reviewer'])
    assert result['configuration']['configured_independent_reviewer_available'] is available
    assert result['independent_reviewers'] == (['reviewer'] if available else [])
    assert result['configuration']['non_admin_developer_available'] is (role in ('write', 'maintain'))
    assert result['decision'] == 'BLOCK' and result['acceptance_complete'] is False


def test_author_with_write_access_cannot_fill_independent_reviewer_requirement():
    result = inspect_configuration({'protected': False}, [], {'user': {'login': 'author'}},
                                   [{'login': 'author', 'role_name': 'write'}], ['author'])
    assert not result['configuration']['configured_independent_reviewer_available']
    assert not result['configuration']['non_admin_developer_available']


def main_ruleset(**overrides):
    rules = [{'type': 'deletion'}, {'type': 'non_fast_forward'},
             {'type': 'required_status_checks', 'parameters': {'strict_required_status_checks_policy': True,
              'required_status_checks': overrides.pop('checks', [{'context': 'trusted-security-pilot', 'integration_id': 15368}])}}]
    ruleset = {'enforcement': 'active', 'target': 'branch', 'bypass_actors': [], 'rules': rules,
               'conditions': {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []}}}
    ruleset.update(overrides)
    return ruleset


def test_hidden_bypass_actors_are_unknown_not_absent():
    hidden = main_ruleset()
    del hidden['bypass_actors']  # 沒有規則集寫入權限的呼叫者看不到此欄位。 / GitHub omits it for callers without ruleset write access
    result = inspect_configuration({'protected': True}, [hidden], {'user': {'login': 'author'}}, [], [])
    assert result['configuration']['active_main_ruleset'] and not result['configuration']['no_bypass']
    assert inspect_configuration({'protected': True}, [main_ruleset()], {'user': {'login': 'author'}}, [], [])[
        'configuration']['no_bypass']


@pytest.mark.parametrize('checks,publisher,legacy,dedicated', [
    ([{'context': 'trusted-security-pilot', 'integration_id': 15368}], None, True, False),
    ([{'context': 'trusted-security-pilot', 'integration_id': 999}], None, False, False),
    ([{'context': 'trusted-security-pilot'}], None, False, False),
    ([{'context': 'epsilon/trusted-merge', 'integration_id': 4242}], 4242, False, True),
    ([{'context': 'epsilon/trusted-merge', 'integration_id': 15368}], 15368, False, False),
    ([{'context': 'epsilon/trusted-merge', 'integration_id': 4242}], None, False, False),
])
def test_required_checks_bind_the_expected_integration(checks, publisher, legacy, dedicated):
    result = inspect_configuration({'protected': True}, [main_ruleset(checks=checks)], {'user': {'login': 'author'}},
                                   [], [], publisher_app_id=publisher)
    assert result['configuration']['required_check_present'] is legacy
    assert result['configuration']['dedicated_app_check_required'] is dedicated
    assert result['decision'] == 'BLOCK'


@pytest.mark.parametrize('codeowners,role,expected', [
    ('* @author\n', 'write', False),
    ('# comment\n* @author @reviewer\n', 'write', True),
    ('* @author @reviewer\n', 'read', False),
    ('* @author @org/team\n', 'write', False),
    (None, 'write', False),
])
def test_base_branch_codeowners_must_name_an_independent_writer(codeowners, role, expected):
    result = inspect_configuration({'protected': True}, [], {'user': {'login': 'author'}},
                                   [{'login': 'reviewer', 'role_name': role}], ['reviewer'], codeowners)
    assert result['configuration']['base_codeowner_independent_reviewer'] is expected
