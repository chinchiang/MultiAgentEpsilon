"""使用注入的代理身分或既有權杖唯讀存取 GitHub。不搜尋權杖、不登入、不重新導向或寫入；沿用發布器的回應大小、期限、JSON 與分頁契約，不取得 App 權杖。

Read-only GitHub API access with injected proxy identity or an existing token.

No token discovery, login, redirects or mutation. Reuse the publisher's bounded
response, deadline, JSON and pagination contracts without obtaining an App token.

Only api.github.com is reachable, so artifact downloads (which redirect to blob
storage) are intentionally unsupported. Without a token, GitHub's anonymous rate
limit applies. 只能連 api.github.com，因此刻意不支援會重新導向至儲存體的 artifact 下載；
未提供權杖時適用 GitHub 匿名速率限制。
"""
import os
import re
import urllib.parse
from .github_http import Denied, GitHub, need, strict_json


class ReadOnlyGitHub(GitHub):
    def __init__(self):
        super().__init__(os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or '')

    def raw(self, url, method='GET', payload=None, authenticated=True, limit=2 * 1024**2):
        need(method == 'GET' and payload is None, 'READ_ONLY_API')
        need(url.startswith('https://api.github.com/'), 'READ_ONLY_DESTINATION')
        return super().raw(url, method, payload, authenticated=bool(self.token), limit=limit)


class GitHubReader:
    """綁定單一儲存庫的 GitHub 讀取；路徑一律相對於該儲存庫。 / GitHub reads bound to one repository; every path is
relative to it."""

    def __init__(self, transport, repo):
        need(re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repo) and repo.split("/")[1] not in (".", ".."), "REPOSITORY")
        self._transport = transport
        self.prefix = f"https://api.github.com/repos/{repo}/"

    def _url(self, path):
        # 分頁由 reader 決定；路徑不得跳出儲存庫。 / The reader owns paging; a path must stay inside the repository.
        parts = urllib.parse.urlsplit(path)
        names = {name for name, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)}
        need(not path.startswith("/") and not parts.scheme and not parts.netloc and not parts.fragment
             and ".." not in urllib.parse.unquote(parts.path).split("/") and not names & {"per_page", "page"},
             "API_PATH")
        return self.prefix + path

    def get(self, path):
        return strict_json(self._transport.raw(self._url(path)))

    def items(self, path, key=None):
        """讀完所有分頁。給 key 時是帶 total_count 的物件列表，每一頁宣稱的總數都必須等於實際讀到的筆數。 / Read
        every page. With key, the response is an object listing whose total_count on every page must equal the items read."""
        url, result, totals = self._url(path), [], []
        for page in range(1, 102):
            separator = "&" if "?" in path else "?"
            items = strict_json(self._transport.raw(url + separator + f"per_page=100&page={page}"))
            if key is not None:
                need(isinstance(items, dict) and type(items.get("total_count")) is int, "PAGINATION_TYPE")
                totals.append(items["total_count"])
                items = items.get(key)
            need(isinstance(items, list), "PAGINATION_TYPE")
            need(len(result) + len(items) <= 10000, "PAGINATION_LIMIT")
            result.extend(items)
            if len(items) < 100:
                need(all(total == len(result) for total in totals), "LISTING_TOTAL")
                return result
        raise Denied("PAGINATION_LIMIT")
