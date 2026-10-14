"""記憶體假 GitHub 傳輸層：依路徑回應並照 GitHub 規則分頁，供 reader 測試使用。 / In-memory fake GitHub transport that
answers by path and paginates the way GitHub does, for reader tests."""
import json
import urllib.parse

from security_harness.github_http import Denied


class FakeGitHub:
    def __init__(self, repo="owner/repo"):
        self.prefix = f"/repos/{repo}/"
        self.routes = {}
        self.requests = []

    def add(self, path, value):
        self.routes[self.prefix + path] = value

    def listing(self, path, key, items, total_count=None):
        """帶 total_count 的物件列表；total_count 可與實際筆數不同。 / An object listing with total_count, which may
        disagree with the actual items."""
        self.routes[self.prefix + path] = Listing(key, items, len(items) if total_count is None else total_count)

    def raw(self, url, method="GET", payload=None, authenticated=True, limit=2 * 1024**2):
        parts = urllib.parse.urlsplit(url)
        assert (parts.scheme, parts.netloc) == ("https", "api.github.com"), url
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True, strict_parsing=bool(parts.query))
        # 重複參數在 GitHub 上靜默生效，這裡直接讓測試失敗。 / GitHub silently accepts repeated parameters; fail the test instead.
        assert len({name for name, _ in query}) == len(query), f"repeated query parameter: {url}"
        self.requests.append((method, parts.path, dict(query)))
        if parts.path not in self.routes:
            raise Denied("GITHUB_HTTP_404")
        value = self.routes[parts.path]
        size = min(int(dict(query).get("per_page", 30)), 100)
        start = (int(dict(query).get("page", 1)) - 1) * size
        if isinstance(value, Listing):
            value = {"total_count": value.total_count, value.key: value.items[start:start + size]}
        elif isinstance(value, list):
            value = value[start:start + size]
        return json.dumps(value).encode()


class Listing:
    def __init__(self, key, items, total_count):
        self.key, self.items, self.total_count = key, items, total_count
