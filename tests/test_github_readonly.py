import pytest
from security_harness.github_readonly import GitHubReader, ReadOnlyGitHub
from security_harness.trusted_publisher import Denied
from tests.fake_github import FakeGitHub


def test_proxy_identity_does_not_require_or_manufacture_local_token(monkeypatch):
    monkeypatch.delenv('GH_TOKEN', raising=False)
    monkeypatch.delenv('GITHUB_TOKEN', raising=False)
    client = ReadOnlyGitHub()
    class Reply:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return b'{"ok":true}'
    class Opener:
        def open(self, request, timeout):
            assert request.full_url == 'https://api.github.com/repos/owner/repo'
            assert request.get_header('Authorization') is None
            return Reply()
    client.opener = Opener()
    assert client.api('/repos/owner/repo') == {'ok': True}


@pytest.mark.parametrize('method', ['POST', 'PUT', 'PATCH', 'DELETE'])
def test_readback_cannot_mutate_remote_state(method):
    with pytest.raises(Denied, match='READ_ONLY_API'):
        ReadOnlyGitHub().api('/repos/owner/repo', method, {'ignored': True})


def test_readback_refuses_other_destinations():
    with pytest.raises(Denied, match='READ_ONLY_DESTINATION'):
        ReadOnlyGitHub().raw('https://other.invalid/')


def test_reader_reads_one_object_relative_to_its_repository():
    github = FakeGitHub('owner/repo')
    github.add('pulls/50', {'number': 50})
    assert GitHubReader(github, 'owner/repo').get('pulls/50') == {'number': 50}


def test_reader_reads_every_page_of_an_array():
    github = FakeGitHub('owner/repo')
    github.add('pulls/50/reviews', [{'id': n} for n in range(250)])
    assert GitHubReader(github, 'owner/repo').items('pulls/50/reviews') == [{'id': n} for n in range(250)]


def test_reader_reads_every_page_of_a_counted_listing():
    github = FakeGitHub('owner/repo')
    github.listing('actions/runs/7/artifacts', 'artifacts', [{'id': n} for n in range(150)])
    assert GitHubReader(github, 'owner/repo').items('actions/runs/7/artifacts', key='artifacts') == [
        {'id': n} for n in range(150)]


@pytest.mark.parametrize('total_count', [149, 151, 250])
def test_reader_refuses_a_listing_whose_total_disagrees_with_its_items(total_count):
    github = FakeGitHub('owner/repo')
    github.listing('actions/runs/7/jobs', 'jobs', [{'id': n} for n in range(150)], total_count=total_count)
    with pytest.raises(Denied, match='^LISTING_TOTAL$'):
        GitHubReader(github, 'owner/repo').items('actions/runs/7/jobs', key='jobs')


@pytest.mark.parametrize('read', ['get', 'items'])
@pytest.mark.parametrize('path', ['/repos/owner/repo/pulls', '../../app', 'pulls/../../../app', 'pulls#x',
                                  'pulls?per_page=100', 'pulls?state=all&page=2', 'pulls?per_page=1&state=all'])
def test_reader_refuses_paths_outside_its_repository_or_with_paging(read, path):
    github = FakeGitHub('owner/repo')
    github.add('pulls', [])
    with pytest.raises(Denied, match='^API_PATH$'):
        getattr(GitHubReader(github, 'owner/repo'), read)(path)
    assert github.requests == []


@pytest.mark.parametrize('key', [None, 'jobs'])
@pytest.mark.parametrize('amount', [10000, 10001])
def test_reader_stops_at_ten_thousand_items(key, amount):
    github = FakeGitHub('owner/repo')
    items = list(range(amount))
    if key is None:
        github.add('jobs', items)
    else:
        github.listing('jobs', key, items)
    reader = GitHubReader(github, 'owner/repo')
    if amount > 10000:
        with pytest.raises(Denied, match='^PAGINATION_LIMIT$'):
            reader.items('jobs', key=key)
    else:
        assert reader.items('jobs', key=key) == items


@pytest.mark.parametrize('key, body', [
    (None, {'total_count': 1, 'jobs': [{}]}),
    ('jobs', [{}]),
    ('jobs', {'total_count': 1, 'artifacts': [{}]}),
    ('jobs', {'total_count': 1, 'jobs': {'id': 1}}),
    ('jobs', {'total_count': '1', 'jobs': [{}]}),
    ('jobs', {'total_count': True, 'jobs': [{}]}),
])
def test_reader_refuses_a_page_of_the_wrong_shape(key, body):
    github = FakeGitHub('owner/repo')
    github.add('actions/runs/7/jobs', body)
    with pytest.raises(Denied, match='^PAGINATION_TYPE$'):
        GitHubReader(github, 'owner/repo').items('actions/runs/7/jobs', key=key)


@pytest.mark.parametrize('repo', ['owner', 'owner/repo/extra', 'owner/../app', '../repo', 'owner/..', 'owner/.',
                                  'owner/re po', ''])
def test_reader_refuses_a_malformed_repository(repo):
    with pytest.raises(Denied, match='^REPOSITORY$'):
        GitHubReader(FakeGitHub(), repo)


def test_reader_accepts_a_repository_named_with_a_leading_dot():
    github = FakeGitHub('owner/.github')
    github.add('pulls/1', {'number': 1})
    assert GitHubReader(github, 'owner/.github').get('pulls/1') == {'number': 1}


HEAD = 'a' * 40


def test_each_check_resolves_to_its_own_attempt_after_a_rerun():
    github = FakeGitHub('owner/repo')
    run = github.workflow_run(7, HEAD, check_suite_id=70)
    first = github.attempt(run, conclusion='failure')
    second = github.attempt(run, conclusion='success')
    reader = GitHubReader(github, 'owner/repo')
    assert [reader.check_source(check)['run_attempt'] for check in (first, second)] == [1, 2]
    assert reader.check_source(first)['run']['id'] == 7


@pytest.mark.parametrize('runs_in_suite', [0, 2])
def test_a_check_whose_suite_is_not_exactly_one_run_is_ambiguous(runs_in_suite):
    github = FakeGitHub('owner/repo')
    run = github.workflow_run(7, HEAD, check_suite_id=70)
    check = github.attempt(run)
    if runs_in_suite == 0:
        check['check_suite']['id'] = 71
        github.listing('actions/runs?check_suite_id=71', 'workflow_runs', [])
    else:
        github.workflow_run(8, HEAD, check_suite_id=70)
    with pytest.raises(Denied, match='^CHECK_RUN_SOURCE_AMBIGUOUS$'):
        GitHubReader(github, 'owner/repo').check_source(check)


@pytest.mark.parametrize('tamper', [
    {'id': 999}, {'run_id': 8}, {'head_sha': 'b' * 40},
    {'check_run_url': 'https://api.github.com/repos/other/repo/check-runs/1000'},
    {'check_run_url': 'https://api.github.com/repos/owner/repo/check-runs/1001'},
    {'run_attempt': 0}, {'run_attempt': '1'}, {'run_attempt': True}, {'run_attempt': None},
])
def test_a_job_that_disagrees_with_its_check_leaves_the_attempt_unresolved(tamper):
    github = FakeGitHub('owner/repo')
    check = github.attempt(github.workflow_run(7, HEAD, check_suite_id=70))
    github.job(check['id']).update(tamper)
    with pytest.raises(Denied, match='^CHECK_ATTEMPT_UNRESOLVED$'):
        GitHubReader(github, 'owner/repo').check_source(check)


@pytest.mark.parametrize('field, value, code', [
    ('check_suite', {'id': '70&head_sha=x'}, 'CHECK_RUN_SOURCE_AMBIGUOUS'),
    ('check_suite', {'id': True}, 'CHECK_RUN_SOURCE_AMBIGUOUS'),
    ('check_suite', None, 'CHECK_RUN_SOURCE_AMBIGUOUS'),
    ('id', '1000', 'CHECK_ATTEMPT_UNRESOLVED'),
    ('id', True, 'CHECK_ATTEMPT_UNRESOLVED'),
])
def test_a_malformed_check_is_refused_before_any_request(field, value, code):
    github = FakeGitHub('owner/repo')
    check = github.attempt(github.workflow_run(7, HEAD, check_suite_id=70))
    check[field] = value
    with pytest.raises(Denied, match=f'^{code}$'):
        GitHubReader(github, 'owner/repo').check_source(check)
    assert github.requests == []


def test_a_check_and_job_that_both_lack_a_head_are_unresolved():
    github = FakeGitHub('owner/repo')
    check = github.attempt(github.workflow_run(7, HEAD, check_suite_id=70))
    del check['head_sha'], github.job(check['id'])['head_sha']
    with pytest.raises(Denied, match='^CHECK_ATTEMPT_UNRESOLVED$'):
        GitHubReader(github, 'owner/repo').check_source(check)


class Pages:
    """每頁內容由測試指定的傳輸層。 / A transport whose pages the test chooses."""

    def __init__(self, page):
        self.page, self.requests = page, []

    def raw(self, url, method='GET', payload=None, authenticated=True, limit=0):
        import json
        import urllib.parse
        parts = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(parts.query))
        self.requests.append((parts.path, query))
        return json.dumps(self.page(int(query['page']))).encode()


def test_exhaustive_reading_stops_only_at_an_empty_page():
    """exhaustive 時不足額的一頁不是結尾：讀到空頁才停；非 exhaustive 仍在第一個不足額的頁停下。

    With exhaustive a short page is not the end: reading stops only at an empty page, while the default still stops
    at the first short page."""
    pages = {1: [{'id': 1}], 2: [{'id': 2}, {'id': 3}], 3: [], 4: [{'id': 4}]}
    transport = Pages(lambda number: pages.get(number, []))
    reader = GitHubReader(transport, 'owner/repo')
    assert reader.items('issues/5/timeline', exhaustive=True) == [{'id': 1}, {'id': 2}, {'id': 3}]
    assert [query['page'] for _, query in transport.requests] == ['1', '2', '3']
    assert all(query['per_page'] == '100' for _, query in transport.requests)
    transport.requests.clear()
    assert reader.items('issues/5/timeline') == [{'id': 1}]
    assert [query['page'] for _, query in transport.requests] == ['1']


def test_exhaustive_reading_of_full_pages_and_of_nothing():
    """剛好滿頁之後接空頁：兩種讀法結果相同；空列表只讀一頁。 / Full pages followed by an empty one read the same
    either way; an empty listing takes one read."""
    github = FakeGitHub('owner/repo')
    github.add('issues/5/timeline', [{'id': n} for n in range(200)])
    github.add('issues/6/timeline', [])
    reader = GitHubReader(github, 'owner/repo')
    assert reader.items('issues/5/timeline', exhaustive=True) == reader.items('issues/5/timeline')
    assert len(reader.items('issues/5/timeline', exhaustive=True)) == 200
    github.requests.clear()
    assert reader.items('issues/6/timeline', exhaustive=True) == []
    assert len(github.requests) == 1


def test_reading_that_never_reaches_an_end_is_refused_after_a_bounded_number_of_pages():
    """每頁都只有一筆、永遠不出現空頁：讀滿固定頁數後以 PAGINATION_LIMIT 拒絕，不會無限讀下去，也不會把讀到的部分當成
    完整結果回傳。

    One item on every page and never an empty one: after a fixed number of pages it is refused with PAGINATION_LIMIT,
    neither reading forever nor returning the partial result as complete."""
    transport = Pages(lambda number: [{'id': number}])
    with pytest.raises(Denied, match='^PAGINATION_LIMIT$'):
        GitHubReader(transport, 'owner/repo').items('issues/5/timeline', exhaustive=True)
    assert [int(query['page']) for _, query in transport.requests] == list(range(1, 102))


def test_exhaustive_reading_still_refuses_more_than_ten_thousand_items():
    github = FakeGitHub('owner/repo')
    github.add('issues/5/timeline', list(range(10001)))
    with pytest.raises(Denied, match='^PAGINATION_LIMIT$'):
        GitHubReader(github, 'owner/repo').items('issues/5/timeline', exhaustive=True)
