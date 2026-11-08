"""共同信任判定透過 GitHub reader 蒐集證據。 / Shared trust decisions collect evidence through the GitHub reader."""
import pytest

from security_harness.github_http import Denied
from security_harness.github_readonly import GitHubReader
from tests.fake_github import FakeGitHub


HEAD = 'b' * 40
PUSHED_AT, APPROVED_AT = '2026-11-08T01:00:00Z', '2026-11-08T01:05:00Z'


def repository():
    github = FakeGitHub()
    pr = {'number': 5, 'state': 'open', 'draft': False, 'user': {'login': 'author'},
          'head': {'sha': HEAD, 'ref': 'feature', 'repo': {'id': 10, 'full_name': 'owner/repo'}},
          'base': {'sha': 'a' * 40, 'ref': 'main', 'repo': {'id': 10}}}
    run = {'head_sha': HEAD, 'head_branch': 'feature', 'head_repository': {'id': 10}}
    github.add('pulls?state=all&head=owner:feature', [pr])
    github.add('issues/5/timeline', [])
    github.add('pulls/5/reviews', [{'id': i, 'state': 'APPROVED', 'commit_id': HEAD, 'submitted_at': APPROVED_AT,
                                'user': {'login': 'reviewer'}} for i in range(1, 102)])
    github.add('rules/branches/main', [{'type': 'pull_request', 'parameters': {'require_last_push_approval': True}}])
    github.cursor_listing('activity?ref=refs/heads/feature', [{'after': HEAD, 'actor': {'login': 'pusher'},
                                                               'timestamp': PUSHED_AT}])
    github.add('collaborators/reviewer/permission', {'role_name': 'write'})
    github.add(f'commits/{HEAD}', {'author': {'login': 'author'}, 'committer': {'login': 'web-flow'}})
    github.add('pulls/5/commits', [{'sha': HEAD, 'author': {'login': 'earlier-author'}}])
    return github, pr, run


def test_publication_evidence_collects_every_page_and_each_permission_once():
    from security_harness.github_trust import GitHubTrust
    github, pr, run = repository()
    evidence = GitHubTrust(GitHubReader(github, 'owner/repo')).publication_review(5, pr, run, 'main')
    assert len(evidence.reviews) == 101
    assert evidence.permissions == {'reviewer': 'write'}
    assert evidence.commit_identities == {'author', 'web-flow', 'earlier-author'}
    assert sum(path.endswith('/collaborators/reviewer/permission') for _, path, _ in github.requests) == 1
    assert {method for method, _, _ in github.requests} == {'GET'}


@pytest.mark.parametrize('attack,code', [
    ('retarget', 'BASE_RETARGETED_UNVERIFIABLE'),
    ('missing_timeline', 'GITHUB_HTTP_404'),
    ('shared_head', 'SHARED_PR_HEAD'),
    ('truncated_commits', 'PR_COMMITS_TRUNCATED'),
    ('missing_permission', 'GITHUB_HTTP_404'),
])
def test_publication_evidence_refuses_unprovable_trust(attack, code):
    from security_harness.github_trust import GitHubTrust
    github, pr, run = repository()
    if attack == 'retarget':
        github.add('issues/5/timeline', [{'event': 'base_ref_changed'}])
    elif attack == 'missing_timeline':
        github.add('issues/5/timeline', Denied('GITHUB_HTTP_404'))
    elif attack == 'shared_head':
        github.add('pulls?state=all&head=owner:feature', [pr, {**pr, 'number': 6}])
    elif attack == 'truncated_commits':
        github.add('pulls/5/commits', [{'sha': HEAD}] * 250)
    else:
        github.add('collaborators/reviewer/permission', Denied('GITHUB_HTTP_404'))
    with pytest.raises(Denied, match=f'^{code}$'):
        GitHubTrust(GitHubReader(github, 'owner/repo')).publication_review(5, pr, run, 'main')


def test_run_base_can_be_checked_without_review_permissions_and_rereads_next_time():
    from security_harness.github_trust import GitHubTrust
    github, pr, run = repository()
    trust = GitHubTrust(GitHubReader(github, 'owner/repo'))
    evidence = trust.run_base(pr, 'main')
    evidence.validate(run)
    evidence.validate({**run, 'run_attempt': 2})
    assert len(github.requests) == 2
    assert all('/reviews' not in path and '/permission' not in path for _, path, _ in github.requests)
    github.add('issues/5/timeline', [{'event': 'base_ref_changed'}])
    with pytest.raises(Denied, match='^BASE_RETARGETED_UNVERIFIABLE$'):
        trust.run_base(pr, 'main').validate(run)


def test_fresh_review_ids_reread_permissions_without_reloading_commit_identities():
    from security_harness.github_trust import GitHubTrust
    github, pr, _ = repository()
    github.add('pulls/5/reviews', [{'id': 11, 'state': 'APPROVED', 'commit_id': HEAD, 'submitted_at': APPROVED_AT,
                                 'user': {'login': 'reviewer'}}])
    trust = GitHubTrust(GitHubReader(github, 'owner/repo'))
    assert trust.review_ids(5, pr, ['reviewer'], {'author'}, 'main') == [11]
    github.add('collaborators/reviewer/permission', {'role_name': 'read'})
    with pytest.raises(Denied, match='^INDEPENDENT_APPROVAL_MISSING$'):
        trust.review_ids(5, pr, ['reviewer'], {'author'}, 'main')
    assert all('/commits/' not in path and not path.endswith('/commits') for _, path, _ in github.requests)


@pytest.mark.parametrize('ids', [[1, 1], ['1']], ids=['duplicate', 'not-int'])
def test_review_listing_with_repeated_or_non_integer_ids_is_refused(ids):
    # 重複或非整數 ID 代表審查清單不可信；不得挑其中一筆當最新狀態。 / Repeated or non-integer IDs make the review
    # listing untrustworthy; none of them may be taken as the latest state.
    from security_harness.github_trust import validate_review
    _, pr, _ = repository()
    reviews = [{'id': i, 'state': 'APPROVED', 'commit_id': HEAD, 'user': {'login': 'reviewer'}} for i in ids]
    with pytest.raises(Denied, match='^REVIEW_ID$'):
        validate_review(pr, reviews, {'reviewer': 'write'}, {'reviewers': ['reviewer']}, set())


def run_base_case():
    _, pr, run = repository()
    return run, pr, [pr], {5: []}


@pytest.mark.parametrize('change,code', [
    ('listing_none', 'PR_LISTING_INCOMPLETE'),
    ('listing_stale_head', 'PR_LISTING_INCOMPLETE'),
    ('history_none', 'BASE_HISTORY_MISSING'),
    ('events_none', 'BASE_HISTORY_MISSING'),
    ('event_not_dict', 'BASE_HISTORY_MISSING'),
    ('event_without_name', 'BASE_HISTORY_MISSING'),
    ('event_name_not_text', 'BASE_HISTORY_MISSING'),
    ('linked_other_base', 'RUN_ORIGINAL_BASE'),
])
def test_run_base_binding_refuses_malformed_or_contradicting_evidence(change, code):
    # 每項都是 GitHub 回傳格式或內容與此 PR 不一致；任何一項都必須以固定診斷碼擋下，不能拋出其他例外或放行。 / Each is
    # GitHub data whose shape or content disagrees with this PR; each must block with its fixed code, never another
    # exception or a pass.
    from security_harness.github_trust import validate_run_base
    run, pr, pulls, histories = run_base_case()
    if change == 'listing_none':
        pulls = None
    elif change == 'listing_stale_head':
        pulls = [{**pr, 'head': {**pr['head'], 'sha': 'c' * 40}}]
    elif change == 'history_none':
        histories = None
    elif change == 'events_none':
        histories = {5: None}
    elif change == 'event_not_dict':
        histories = {5: ['labeled']}
    elif change == 'event_without_name':
        histories = {5: [{}]}
    elif change == 'event_name_not_text':
        histories = {5: [{'event': 1}]}
    else:
        run = {**run, 'pull_requests': [{'number': 5, 'base': {'ref': 'evil'}}]}
    with pytest.raises(Denied, match=f'^{code}$'):
        validate_run_base(run, pr, pulls, 'main', histories)


def test_run_snapshots_of_other_prs_or_the_same_base_do_not_block():
    # run 的關聯 PR 快照只能限縮信任：只有此 PR 的快照指向別的 base 才拒絕。 / A run's linked PR snapshots may only
    # constrain trust: only this PR's snapshot naming another base refuses.
    from security_harness.github_trust import validate_run_base
    run, pr, pulls, histories = run_base_case()
    run = {**run, 'pull_requests': [{'number': 5, 'base': {'ref': 'main'}}, {'number': 6, 'base': {'ref': 'evil'}},
                                    {'number': 5}]}
    validate_run_base(run, pr, pulls, 'main', histories)


@pytest.mark.parametrize('change,code', [
    ('rule_off', 'LAST_PUSH_APPROVAL'),
    ('approved_before_push', 'INDEPENDENT_APPROVAL_MISSING'),
    ('approved_by_pusher', 'INDEPENDENT_APPROVAL_MISSING'),
    ('draft', 'PR_NOT_REVIEWABLE'),
])
def test_publisher_applies_the_guard_rules_to_push_time_pusher_and_ruleset(change, code):
    # 先前 publisher 不看推送時間、推送者與規則集，只有 guard 擋；兩邊改走同一套規則。 / The publisher used to ignore
    # the push time, the pusher and the ruleset that only the guard checked; both now apply one rule set.
    from security_harness.github_trust import GitHubTrust
    github, pr, _ = repository()
    review = {'id': 11, 'state': 'APPROVED', 'commit_id': HEAD, 'submitted_at': APPROVED_AT,
              'user': {'login': 'reviewer'}}
    if change == 'rule_off':
        github.add('rules/branches/main', [{'type': 'pull_request', 'parameters': {}}])
    elif change == 'approved_before_push':
        review['submitted_at'] = PUSHED_AT
    elif change == 'approved_by_pusher':
        github.cursor_listing('activity?ref=refs/heads/feature', [{'after': HEAD, 'actor': {'login': 'reviewer'},
                                                                   'timestamp': PUSHED_AT}])
    else:
        pr = {**pr, 'draft': True}
    github.add('pulls/5/reviews', [review])
    with pytest.raises(Denied, match=f'^{code}$'):
        GitHubTrust(GitHubReader(github, 'owner/repo')).review_ids(5, pr, ['reviewer'], set(), 'main')


def test_review_decision_without_established_push_is_refused():
    from security_harness.github_trust import review_decision
    _, pr, _ = repository()
    review = {'id': 11, 'state': 'APPROVED', 'commit_id': HEAD, 'submitted_at': APPROVED_AT,
              'user': {'login': 'reviewer'}}
    with pytest.raises(Denied, match='^LAST_PUSH_UNKNOWN$'):
        review_decision(pr, [review], {'reviewer': 'write'}, ['reviewer'], set(), None)


def test_closed_prs_or_other_heads_do_not_count_as_a_shared_head():
    # 同一 head 的已關閉 PR、或其他分支的開放 PR，都不是共用 head。 / A closed PR on the same head, or an open PR on
    # another branch, is no shared head.
    from security_harness.github_trust import GitHubTrust
    github, pr, _ = repository()
    other_branch = {**pr, 'number': 7, 'head': {**pr['head'], 'ref': 'other'}}
    github.add('pulls?state=all&head=owner:feature', [pr, {**pr, 'number': 4, 'state': 'closed'}, other_branch])
    assert GitHubTrust(GitHubReader(github, 'owner/repo')).review_ids(5, pr, ['reviewer'], set(), 'main')


def test_base_branch_outside_the_branch_name_pattern_is_never_put_in_a_path():
    from security_harness.github_trust import GitHubTrust
    github, pr, _ = repository()
    with pytest.raises(Denied, match='^BASE_BRANCH$'):
        GitHubTrust(GitHubReader(github, 'owner/repo')).review_ids(5, pr, ['reviewer'], set(), 'main?x=1')
    assert not any('/rules/' in path for _, path, _ in github.requests)
