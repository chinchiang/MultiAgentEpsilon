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
