"""規則集排程監看：線上規則集弱於稽核要求時必須失敗，讀不到時不得默默通過。

Scheduled ruleset monitor: a live ruleset weaker than the audit requires must fail, and an unreadable one
must never pass silently."""
import copy
import json

import pytest

from scripts import monitor_ruleset

BRANCH = {'protected': True, 'commit': {'sha': 'a' * 40}}


def template():
    """與 docs/github-main-ruleset.json 相同的內容（另有測試綁定），加上線上規則集的 id 與更新時間。寫在測試內，突變快照
    不含 docs/ 也能執行。 / The content of docs/github-main-ruleset.json (bound by a separate test) plus the live
    ruleset's id and update time. Inline, so it also runs in the mutation snapshot, which has no docs/."""
    return {
        'name': 'Security pilot — protected main', 'target': 'branch', 'enforcement': 'active', 'bypass_actors': [],
        'conditions': {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []}},
        'rules': [
            {'type': 'deletion'},
            {'type': 'non_fast_forward'},
            {'type': 'pull_request', 'parameters': {
                'required_approving_review_count': 1, 'dismiss_stale_reviews_on_push': True,
                'require_code_owner_review': True, 'require_last_push_approval': True,
                'require_extra_approval_for_unattributed_changes': True, 'required_review_thread_resolution': True,
                'allowed_merge_methods': ['merge']}},
            {'type': 'required_status_checks', 'parameters': {
                'required_status_checks': [{'context': 'trusted-security-pilot', 'integration_id': 15368}],
                'strict_required_status_checks_policy': True}},
        ],
        'id': 24512048, 'updated_at': '2026-11-07T18:21:10.306+08:00',
    }


def live_on_20261114():
    """2026-11-14 讀回的線上規則集 24512048：合併方式仍開放 squash 與 rebase。 / Ruleset 24512048 as read back on
    November 14, 2026: squash and rebase merges were still allowed."""
    ruleset = template()
    ruleset['rules'][2]['parameters'].update(required_reviewers=[], allowed_merge_methods=['merge', 'squash', 'rebase'])
    ruleset['rules'][3]['parameters'].update(do_not_enforce_on_create=False)
    return ruleset


class Reader:
    repository = 'owner/repo'

    def __init__(self, rulesets, branch=BRANCH, fail=None):
        self.rulesets, self.branch, self.fail, self.paths = rulesets, branch, fail, []

    def get(self, path):
        self.paths.append(path)
        if self.fail == path:
            raise RuntimeError('unreadable')
        if path == 'branches/main':
            return self.branch
        return next(r for r in self.rulesets if path == f"rulesets/{r['id']}")

    def items(self, path):
        self.paths.append(path)
        if self.fail == path:
            raise RuntimeError('unreadable')
        return [{'id': r['id']} for r in self.rulesets]


def test_the_template_ruleset_is_ok():
    result = monitor_ruleset.assess(BRANCH, [template()])
    assert (result['decision'], result['failed'], result['unknown']) == ('OK', [], [])
    assert all(result['protections'].values())
    assert result['rulesets'] == [{'id': 24512048, 'name': 'Security pilot — protected main',
                                   'updated_at': '2026-11-07T18:21:10.306+08:00'}]


def test_the_live_ruleset_of_20261114_is_reported_as_drift():
    result = monitor_ruleset.assess(BRANCH, [live_on_20261114()])
    assert (result['decision'], result['failed'], result['unknown']) == ('DRIFT', ['merge_commit_only'], [])


@pytest.mark.parametrize('weaken,failed', [
    (lambda r: r['bypass_actors'].append({'actor_id': 1}), ['no_bypass']),
    (lambda r: r['rules'][2]['parameters']['allowed_merge_methods'].append('squash'), ['merge_commit_only']),
    (lambda r: r['rules'][2]['parameters'].update(require_last_push_approval=False), ['independent_review_required']),
    (lambda r: r['rules'][3]['parameters']['required_status_checks'][0].update(integration_id=1),
     ['required_check_present']),
    (lambda r: r['rules'][3]['parameters'].update(strict_required_status_checks_policy=False), ['strict_checks']),
    (lambda r: r['rules'].pop(0), ['no_delete_or_force_push']),
    (lambda r: r['rules'][2]['parameters'].update(required_review_thread_resolution=False),
     ['review_thread_resolution_required']),
    (lambda r: r['rules'][2]['parameters'].update(require_extra_approval_for_unattributed_changes=False),
     ['unattributed_changes_extra_approval']),
], ids=['bypass', 'squash', 'last-push', 'check-source', 'not-strict', 'deletion', 'threads', 'unattributed'])
def test_each_weakening_is_drift_naming_exactly_the_lost_protection(weaken, failed):
    ruleset = template()
    weaken(ruleset)
    result = monitor_ruleset.assess(BRANCH, [ruleset])
    assert (result['decision'], result['failed'], result['unknown']) == ('DRIFT', failed, [])


def test_a_disabled_or_missing_ruleset_is_drift():
    disabled = template()
    disabled['enforcement'] = 'disabled'
    for rulesets in ([], [disabled]):
        result = monitor_ruleset.assess(BRANCH, rulesets)
        assert result['decision'] == 'DRIFT' and result['unknown'] == [] and result['rulesets'] == []
        assert {'active_main_ruleset', 'no_bypass', 'required_check_present'} <= set(result['failed'])


def test_an_unprotected_branch_is_drift():
    result = monitor_ruleset.assess({'protected': False}, [template()])
    assert (result['decision'], result['failed']) == ('DRIFT', ['main_protected'])


def test_a_bypass_list_the_token_cannot_read_is_unknown_not_drift():
    hidden = template()
    del hidden['bypass_actors']
    result = monitor_ruleset.assess(BRANCH, [hidden])
    assert (result['decision'], result['failed'], result['unknown']) == ('OK', [], ['no_bypass'])
    assert result['protections']['no_bypass'] is False


def test_a_hidden_bypass_list_never_hides_other_drift_or_a_visible_bypass():
    hidden = live_on_20261114()
    del hidden['bypass_actors']
    result = monitor_ruleset.assess(BRANCH, [hidden])
    assert (result['decision'], result['failed'], result['unknown']) == ('DRIFT', ['merge_commit_only'], ['no_bypass'])
    visible = template()
    visible.update(id=2, bypass_actors=[{'actor_id': 5}])
    result = monitor_ruleset.assess(BRANCH, [hidden, visible])
    assert 'no_bypass' in result['failed'] and result['unknown'] == []


def test_monitor_reads_only_the_branch_and_the_rulesets(tmp_path, capsys):
    reader = Reader([template()])
    assert monitor_ruleset.main(['--output', str(tmp_path / 'out.json')], reader) == 0
    assert reader.paths == ['branches/main', 'rulesets?includes_parents=true', 'rulesets/24512048']
    written = json.loads((tmp_path / 'out.json').read_text())
    assert written == json.loads(capsys.readouterr().out)
    assert (written['decision'], written['repository'], written['main_sha']) == ('OK', 'owner/repo', 'a' * 40)


def test_drift_exits_nonzero_and_names_the_protection(tmp_path, capsys):
    assert monitor_ruleset.main(['--output', str(tmp_path / 'out.json')], Reader([live_on_20261114()])) == 1
    assert json.loads((tmp_path / 'out.json').read_text())['failed'] == ['merge_commit_only']
    assert '::warning::' not in capsys.readouterr().out


def test_unknown_bypass_exits_zero_with_a_warning(tmp_path, capsys):
    hidden = template()
    del hidden['bypass_actors']
    assert monitor_ruleset.main(['--output', str(tmp_path / 'out.json')], Reader([hidden])) == 0
    assert '::warning::no_bypass is unknown' in capsys.readouterr().out


@pytest.mark.parametrize('path', ['branches/main', 'rulesets?includes_parents=true', 'rulesets/24512048'])
def test_an_unreadable_branch_or_ruleset_is_an_error_not_a_pass(tmp_path, path):
    assert monitor_ruleset.main(['--output', str(tmp_path / 'out.json')], Reader([template()], fail=path)) == 1
    written = json.loads((tmp_path / 'out.json').read_text())
    assert written == {'decision': 'ERROR', 'failed': [], 'unknown': [], 'errors': ['RuntimeError']}


def test_assess_does_not_modify_its_input():
    ruleset = live_on_20261114()
    before = copy.deepcopy(ruleset)
    monitor_ruleset.assess(BRANCH, [ruleset])
    assert ruleset == before


def test_deletion_and_force_push_rules_alone_satisfy_that_protection():
    # 只剩這兩條規則時，該項仍成立，其餘各項另行回報。 / With only these two rules left, that protection still holds
    # and the others are reported separately.
    ruleset = template()
    ruleset['rules'] = ruleset['rules'][:2]
    result = monitor_ruleset.assess(BRANCH, [ruleset])
    assert result['protections']['no_delete_or_force_push'] is True
    assert result['failed'] == ['independent_review_required', 'merge_commit_only', 'required_check_present',
                                'review_thread_resolution_required', 'strict_checks',
                                'unattributed_changes_extra_approval']


def test_a_hidden_bypass_list_beside_a_visible_empty_one_is_still_unknown():
    hidden = template()
    del hidden['bypass_actors']
    visible = template()
    visible['id'] = 2
    result = monitor_ruleset.assess(BRANCH, [hidden, visible])
    assert (result['decision'], result['failed'], result['unknown']) == ('OK', [], ['no_bypass'])
