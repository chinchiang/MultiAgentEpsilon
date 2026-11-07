"""共同信任判定透過 GitHub reader 蒐集證據。 / Shared trust decisions collect evidence through the GitHub reader."""
import pytest

from security_harness.github_http import Denied
from security_harness.github_readonly import GitHubReader
from tests.fake_github import FakeGitHub


HEAD = 'b' * 40


def repository():
    github = FakeGitHub()
    pr = {'number': 5, 'state': 'open', 'user': {'login': 'author'},
          'head': {'sha': HEAD, 'ref': 'feature', 'repo': {'id': 10, 'full_name': 'owner/repo'}},
          'base': {'sha': 'a' * 40, 'ref': 'main', 'repo': {'id': 10}}}
    run = {'head_sha': HEAD, 'head_branch': 'feature', 'head_repository': {'id': 10}}
    github.add('pulls?state=all&head=owner:feature', [pr])
    github.add('issues/5/timeline', [])
    github.add('pulls/5/reviews', [{'id': i, 'state': 'APPROVED', 'commit_id': HEAD,
                                'user': {'login': 'reviewer'}} for i in range(1, 102)])
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
    github.add('pulls/5/reviews', [{'id': 11, 'state': 'APPROVED', 'commit_id': HEAD,
                                 'user': {'login': 'reviewer'}}])
    trust = GitHubTrust(GitHubReader(github, 'owner/repo'))
    assert trust.review_ids(5, pr, ['reviewer'], {'author'}) == [11]
    github.add('collaborators/reviewer/permission', {'role_name': 'read'})
    with pytest.raises(Denied, match='^INDEPENDENT_APPROVAL_MISSING$'):
        trust.review_ids(5, pr, ['reviewer'], {'author'})
    assert all('/commits/' not in path and not path.endswith('/commits') for _, path, _ in github.requests)
