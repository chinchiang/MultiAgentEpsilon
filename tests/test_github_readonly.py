import pytest
from security_harness.github_readonly import ReadOnlyGitHub
from security_harness.trusted_publisher import Denied


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
