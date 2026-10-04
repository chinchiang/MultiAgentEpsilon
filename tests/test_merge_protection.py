from scripts.audit_merge_protection import inspect_configuration


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
