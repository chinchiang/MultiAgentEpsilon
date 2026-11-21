"""GitHub 傳輸層的呼叫預算與保留呼叫：預算或期限用完後，仍須能發布失敗結果並撤銷權杖。

Call budget and reserved calls of the GitHub transport: once the budget or the deadline is spent, a failure
must still be publishable and the token must still be revocable."""
import pytest

from security_harness import github_http
from security_harness.github_http import Denied, GitHub

CHECK_RUNS = 'https://api.github.com/repos/owner/repo/check-runs'
REVOKE = 'https://api.github.com/installation/token'


class Opener:
    def __init__(self):
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request.get_method(), request.full_url, timeout))
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, limit):
        return b'{}'


def spent(monkeypatch, *, by):
    transport = GitHub('token')
    transport.opener = Opener()
    if by == 'deadline':
        transport.deadline = github_http.time.monotonic() - 1
    else:
        transport.calls = github_http.API_CALL_BUDGET
    return transport


@pytest.mark.parametrize('by', ['deadline', 'calls'])
def test_spent_budget_refuses_ordinary_calls(monkeypatch, by):
    transport = spent(monkeypatch, by=by)
    for method, url in (('GET', 'https://api.github.com/repos/owner/repo'),
                        ('DELETE', 'https://api.github.com/repos/owner/repo/git/refs/heads/x'),
                        ('POST', 'https://api.github.com/repos/owner/repo/issues')):
        with pytest.raises(Denied, match='^API_BUDGET$'):
            transport.raw(url, method, {} if method == 'POST' else None)
    assert transport.opener.calls == []


@pytest.mark.parametrize('by', ['deadline', 'calls'])
def test_one_result_publication_survives_a_spent_budget(monkeypatch, by):
    transport = spent(monkeypatch, by=by)
    transport.raw(CHECK_RUNS, 'POST', {})
    assert transport.opener.calls == [('POST', CHECK_RUNS, 20)]
    with pytest.raises(Denied, match='^API_BUDGET$'):
        transport.raw(CHECK_RUNS, 'POST', {})


@pytest.mark.parametrize('by', ['deadline', 'calls'])
def test_one_token_revocation_survives_a_spent_budget(monkeypatch, by):
    # 驗證若耗盡 240 秒，撤銷呼叫原本會被拒絕，安裝權杖就活滿一小時。 / When verification used up the 240 seconds
    # the revocation used to be refused, leaving the installation token alive for its full hour.
    transport = spent(monkeypatch, by=by)
    transport.raw(REVOKE, 'DELETE')
    assert transport.opener.calls == [('DELETE', REVOKE, 20)]
    with pytest.raises(Denied, match='^API_BUDGET$'):
        transport.raw(REVOKE, 'DELETE')
    assert len(transport.opener.calls) == 1


def test_the_reserved_revocation_is_separate_from_the_reserved_publication(monkeypatch):
    transport = spent(monkeypatch, by='deadline')
    transport.raw(CHECK_RUNS, 'POST', {})
    transport.raw(REVOKE, 'DELETE')
    assert [call[0] for call in transport.opener.calls] == ['POST', 'DELETE']


def test_reserved_calls_do_not_consume_the_ordinary_budget():
    transport = GitHub('token')
    transport.opener = Opener()
    transport.raw(CHECK_RUNS, 'POST', {})
    transport.raw(REVOKE, 'DELETE')
    assert transport.calls == 0
    transport.raw('https://api.github.com/repos/owner/repo')
    assert transport.calls == 1


@pytest.mark.parametrize('method,url', [
    ('GET', REVOKE), ('POST', REVOKE),
    ('DELETE', 'https://api.github.com/installation/token/extra'),
    ('DELETE', 'https://api.github.com/app/installations/1/access_tokens')])
def test_only_the_exact_revocation_call_is_reserved(method, url):
    transport = spent(None, by='deadline')
    with pytest.raises(Denied, match='^API_BUDGET$'):
        transport.raw(url, method, {} if method == 'POST' else None)
