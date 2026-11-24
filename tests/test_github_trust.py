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
    # PR 列表一次、timeline 一次：空的 timeline 第一頁就是空頁，不必再讀。 / One read of the PR listing and one of the
    # timeline: an empty timeline ends at its first, empty page.
    assert [query.get('page') for _, path, query in github.requests if path.endswith('/timeline')] == ['1']
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


def test_publication_reverification_refuses_reviews_that_changed_since_collection():
    # 蒐集證據後、發布綠燈前，核准可能被換成另一筆同樣有效的審查；重查必須以精確拒絕碼擋下。 / Between collecting
    # evidence and publishing green, the approval may be replaced by another equally valid review; the recheck
    # must refuse it with its exact code.
    from security_harness.github_trust import GitHubTrust
    trust = GitHubTrust(reader=None)
    seen = []
    trust.run_base = lambda pr, base: type('Base', (), {'validate': lambda self, run: seen.append(('base', base, run))})()
    trust.review_ids = lambda number, pr, reviewers, excluded, base: seen.append((number, reviewers, excluded, base)) or [12]
    proof = {'excluded_identities': ['author'], 'review_ids': [11]}
    with pytest.raises(Denied, match='^REVIEW_CHANGED$'):
        trust.reverify_publication(5, {'number': 5}, {'id': 100}, ['reviewer'], proof, 'main')
    assert seen == [('base', 'main', {'id': 100}), (5, ['reviewer'], {'author'}, 'main')]
    assert trust.reverify_publication(5, {'number': 5}, {'id': 100}, ['reviewer'],
                                      {'excluded_identities': ['author'], 'review_ids': [12]}, 'main') is None


def moved_twin(**fields):
    """同一分支的另一個 PR，head 已移到別的 commit。 / Another PR of the same branch whose head moved to another commit."""
    return {'number': 6, 'state': 'closed', 'base': {'ref': 'main', 'repo': {'id': 10}},
            'head': {'sha': 'c' * 40, 'ref': 'feature', 'repo': {'id': 10, 'full_name': 'owner/repo'}}, **fields}


RUN_CREATED = '2026-11-01T10:00:00Z'


@pytest.mark.parametrize('twin,histories,code', [
    # 指向別的 base，在 run 建立之後才關閉：可能就是這個 run 的來源。 / Targets another base and closed only after the
    # run was created: it may be this run's source.
    (moved_twin(base={'ref': 'evil', 'repo': {'id': 10}}, closed_at='2026-11-01T10:00:01Z'), {5: [], 6: []},
     'FOREIGN_BASE_PR'),
    # 與 run 建立同一秒關閉也不算「之前」。 / Closing in the very second the run was created is not before it.
    (moved_twin(base={'ref': 'evil', 'repo': {'id': 10}}, closed_at=RUN_CREATED), {5: [], 6: []}, 'FOREIGN_BASE_PR'),
    # 仍開啟、沒有關閉時間或時間格式不符，都不能證明它不是來源。 / Still open, no close time or a malformed one: none
    # proves it is not the source.
    (moved_twin(base={'ref': 'evil', 'repo': {'id': 10}}, state='open', closed_at=None), {5: [], 6: []},
     'FOREIGN_BASE_PR'),
    (moved_twin(base={'ref': 'evil', 'repo': {'id': 10}}), {5: [], 6: []}, 'FOREIGN_BASE_PR'),
    (moved_twin(base={'ref': 'evil', 'repo': {'id': 10}}, closed_at='yesterday'), {5: [], 6: []}, 'FOREIGN_BASE_PR'),
    # base 目前是 main，但曾改過 base；或它的 timeline 沒有讀到。 / Its base is main now but was retargeted, or its
    # timeline was never read.
    (moved_twin(closed_at='2026-11-01T10:00:01Z'), {5: [], 6: [{'event': 'base_ref_changed'}]},
     'BASE_RETARGETED_UNVERIFIABLE'),
    (moved_twin(closed_at='2026-11-01T10:00:01Z'), {5: []}, 'BASE_HISTORY_MISSING'),
])
def test_same_branch_pr_whose_head_moved_can_still_be_the_run_source(twin, histories, code):
    """PR 關閉前把分支移到別的 commit，就不再記錄 run 的 commit；只要無法證明它在 run 建立前已關閉，仍視為可能的來源。

    A PR whose branch moved to another commit before it closed no longer records the run's commit; unless it provably
    closed before the run was created it still counts as a possible source."""
    from security_harness.github_trust import validate_run_base
    run, pr, pulls, _ = run_base_case()
    with pytest.raises(Denied, match=f'^{code}$'):
        validate_run_base({**run, 'created_at': RUN_CREATED}, pr, [*pulls, twin], 'main', histories)


@pytest.mark.parametrize('created', [RUN_CREATED, None, 'soon'])
@pytest.mark.parametrize('closed_at', ['2026-11-01T09:59:59Z', '2026-10-20T10:00:00Z', None])
def test_same_branch_pr_into_another_base_blocks_whenever_it_closed(created, closed_at):
    """指向其他 base 的同分支 PR 一律拒絕，不看關閉時間：run 的建立時間晚於觸發它的事件，搶在 run 建立前關閉不能證明
    它不是來源（PR #107 的時間條件可被這樣繞過）。

    A same-branch PR into another base always blocks, whatever its close time: a run is created after the event that
    triggered it, so closing before the run was created proves nothing (this raced the time condition of PR #107)."""
    from security_harness.github_trust import validate_run_base
    run, pr, pulls, histories = run_base_case()
    twin = moved_twin(base={'ref': 'evil', 'repo': {'id': 10}}, closed_at=closed_at)
    with pytest.raises(Denied, match='^FOREIGN_BASE_PR$'):
        validate_run_base({**run, 'created_at': created}, pr, [*pulls, twin], 'main', {**histories, 6: []})


@pytest.mark.parametrize('closed_at,read', [
    # 早 1 秒、早將近 7 天、剛好 7 天：都在延遲上限內，必須讀它的改 base 紀錄。 / One second, almost seven days and
    # exactly seven days earlier: all within the delay bound, so its retarget history must be read.
    ('2026-11-01T09:59:59Z', True), ('2026-10-25T10:00:01Z', True), ('2026-10-25T10:00:00Z', True),
    # 超過 7 天：省略。 / More than seven days: skipped.
    ('2026-10-25T09:59:59Z', False), ('2026-01-01T00:00:00Z', False),
    # 沒有關閉時間或格式不符：不能省略。 / No close time or a malformed one: never skipped.
    (None, True), ('last week', True),
])
def test_retarget_history_of_a_moved_same_branch_pr_is_read_within_the_delay_bound(closed_at, read):
    """base 為 main、head 已移走的同分支 PR：只有早在延遲上限（7 天）之前就關閉才省略它的改 base 紀錄。

    A same-branch PR into main whose head moved: its retarget history is skipped only when it closed earlier than the
    delay bound (seven days)."""
    from security_harness.github_trust import SOURCE_DELAY_LIMIT, validate_run_base
    assert SOURCE_DELAY_LIMIT.total_seconds() == 7 * 24 * 3600
    run, pr, pulls, histories = run_base_case()
    twin = moved_twin(closed_at=closed_at)
    run = {**run, 'created_at': RUN_CREATED}
    if read:
        with pytest.raises(Denied, match='^BASE_HISTORY_MISSING$'):
            validate_run_base(run, pr, [*pulls, twin], 'main', histories)
        with pytest.raises(Denied, match='^BASE_RETARGETED_UNVERIFIABLE$'):
            validate_run_base(run, pr, [*pulls, twin], 'main', {**histories, 6: [{'event': 'base_ref_changed'}]})
        validate_run_base(run, pr, [*pulls, twin], 'main', {**histories, 6: []})
    else:
        validate_run_base(run, pr, [*pulls, twin], 'main', histories)


@pytest.mark.parametrize('created', [RUN_CREATED, None, 'soon'])
def test_run_without_a_usable_creation_time_excludes_no_same_branch_pr(created):
    """run 的建立時間讀不到或格式不符時，不能用它省略任何同分支 PR 的改 base 紀錄。

    A run whose creation time is missing or malformed skips no same-branch PR's retarget history."""
    from security_harness.github_trust import validate_run_base
    run, pr, pulls, histories = run_base_case()
    twin = moved_twin(closed_at='2026-01-01T00:00:00Z')
    run = {**run, 'created_at': created}
    if created == RUN_CREATED:
        # 早在延遲上限之前就關閉：不需要它的 timeline。 / Closed earlier than the delay bound: its timeline is not needed.
        validate_run_base(run, pr, [*pulls, twin], 'main', histories)
    else:
        with pytest.raises(Denied, match='^BASE_HISTORY_MISSING$'):
            validate_run_base(run, pr, [*pulls, twin], 'main', histories)


@pytest.mark.parametrize('field,value', [('ref', 'other'), ('repo', {'id': 20, 'full_name': 'fork/repo'})])
def test_pr_of_another_branch_or_repository_is_never_a_possible_source(field, value):
    """另一個分支或 fork 的 PR 不可能產生回報此分支的 run；它指向別的 base 也不阻擋。

    A PR of another branch or fork cannot produce a run that reports this branch; its other base does not block."""
    from security_harness.github_trust import validate_run_base
    run, pr, pulls, histories = run_base_case()
    twin = moved_twin(base={'ref': 'evil', 'repo': {'id': 10}}, state='open', closed_at=None)
    twin['head'] = {**twin['head'], field: value}
    validate_run_base({**run, 'created_at': RUN_CREATED}, pr, [*pulls, twin], 'main', histories)


def test_run_base_reads_each_possible_source_timeline_once_and_skips_ruled_out_prs():
    """timeline 只為必須檢查的 PR 讀取，同一 PR 在多個 run 之間只讀一次；早在延遲上限之前就關閉的 PR 不讀。

    Timelines are read only for PRs that must be checked, once per PR across runs; a PR that closed earlier than the
    delay bound is never read."""
    from security_harness.github_trust import GitHubTrust
    github, pr, run = repository()
    live = moved_twin(number=6, closed_at='2026-11-01T10:00:01Z')
    gone = moved_twin(number=7, closed_at='2026-10-25T09:59:59Z')
    github.add('pulls?state=all&head=owner:feature', [pr, live, gone])
    github.add('issues/6/timeline', [])
    evidence = GitHubTrust(GitHubReader(github, 'owner/repo')).run_base(pr, 'main')
    evidence.validate({**run, 'created_at': RUN_CREATED})
    evidence.validate({**run, 'created_at': RUN_CREATED})
    read = [path for _, path, query in github.requests if path.endswith('/timeline') and query['page'] == '1']
    assert sorted(read) == ['/repos/owner/repo/issues/5/timeline', '/repos/owner/repo/issues/6/timeline']
    # 較早建立的 run 離 #7 的關閉不到 7 天，必須讀它的 timeline；它曾改 base，所以拒絕。 / An earlier run is within
    # seven days of #7 closing, so its timeline must be read; it was retargeted, so it is refused.
    github.add('issues/7/timeline', [{'event': 'base_ref_changed'}])
    with pytest.raises(Denied, match='^BASE_RETARGETED_UNVERIFIABLE$'):
        evidence.validate({**run, 'created_at': '2026-11-01T09:00:00Z'})
    read = [path for _, path, query in github.requests if path.endswith('/timeline') and query['page'] == '1']
    assert sorted(read) == ['/repos/owner/repo/issues/5/timeline', '/repos/owner/repo/issues/6/timeline',
                            '/repos/owner/repo/issues/7/timeline']



@pytest.mark.parametrize('event,code', [
    ('base_ref_changed', 'BASE_RETARGETED_UNVERIFIABLE'),
    ('automatic_base_change_succeeded', 'BASE_RETARGETED_UNVERIFIABLE'),
    ('automatic_base_change_failed', None),
    ('renamed', None),
])
def test_an_automatic_retarget_counts_as_a_changed_base(event, code):
    """base 分支被合併刪除後 GitHub 自動改 base，timeline 記的是 automatic_base_change_succeeded，不是
    base_ref_changed；兩者都代表 run 可能取自另一個 base 的 workflow。沒有改成的嘗試與無關事件不算。

    When a base branch is merged and deleted GitHub retargets the PR itself and records
    automatic_base_change_succeeded, not base_ref_changed; either means a run may have used another base's workflow.
    A failed attempt and an unrelated event do not count."""
    from security_harness.github_trust import RETARGET_EVENTS, GitHubTrust
    github, pr, run = repository()
    github.add('issues/5/timeline', [{'event': 'labeled'}, {'event': event}])
    evidence = GitHubTrust(GitHubReader(github, 'owner/repo')).run_base(pr, 'main')
    assert (event in RETARGET_EVENTS) == (code is not None)
    if code is None:
        evidence.validate(run)
    else:
        with pytest.raises(Denied, match=f'^{code}$'):
            evidence.validate(run)


class ShortPages:
    """每頁筆數由測試指定的傳輸層：模擬 GitHub 過濾事件後回傳不足額、但不是最後一頁的分頁。 / A transport whose page
    sizes the test chooses: a page GitHub filtered below the page size that is still not the last."""

    def __init__(self, pages):
        self.pages, self.read = pages, []

    def raw(self, url, method='GET', payload=None, authenticated=True, limit=0):
        import json
        import urllib.parse
        parts = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(parts.query))
        self.read.append((parts.path, int(query['page'])))
        if parts.path.endswith('/pulls'):
            return json.dumps(self.pages['pulls'] if query['page'] == '1' else []).encode()
        return json.dumps(self.pages['timeline'].get(int(query['page']), [])).encode()


def test_a_retarget_behind_a_short_timeline_page_is_still_read():
    """timeline 的一頁不足額不代表後面沒有事件：讀到空頁才停，藏在後面分頁的改 base 紀錄仍會被讀到。

    A short timeline page does not mean no events follow: reading stops only at an empty page, so a retarget on a
    later page is still seen."""
    from security_harness.github_trust import GitHubTrust
    _, pr, run = repository()
    transport = ShortPages({'pulls': [pr], 'timeline': {1: [{'event': 'labeled'}], 2: [{'event': 'base_ref_changed'}]}})
    reader = GitHubReader(transport, 'owner/repo')
    assert reader.items('issues/5/timeline') == [{'event': 'labeled'}]
    assert reader.items('issues/5/timeline', exhaustive=True) == [{'event': 'labeled'}, {'event': 'base_ref_changed'}]
    with pytest.raises(Denied, match='^BASE_RETARGETED_UNVERIFIABLE$'):
        GitHubTrust(reader).run_base(pr, 'main').validate(run)
    assert transport.read[-3:] == [('/repos/owner/repo/issues/5/timeline', page) for page in (1, 2, 3)]
