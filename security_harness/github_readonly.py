"""Read-only GitHub API access with injected proxy identity or an existing token.

No token discovery, login, redirects or mutation. Reuse the publisher's bounded
response, deadline, JSON and pagination contracts without obtaining an App token.
"""
import os
from .trusted_publisher import GitHub, need


class ReadOnlyGitHub(GitHub):
    def __init__(self):
        super().__init__(os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or '')

    def raw(self, url, method='GET', payload=None, authenticated=True, limit=2 * 1024**2):
        need(method == 'GET' and payload is None, 'READ_ONLY_API')
        need(url.startswith('https://api.github.com/'), 'READ_ONLY_DESTINATION')
        return super().raw(url, method, payload, authenticated=bool(self.token), limit=limit)
