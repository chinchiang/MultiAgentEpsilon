"""GitHub REST 傳輸層與固定診斷碼：呼叫預算、期限、回應大小上限、權杖目的地、不跟隨重新導向與嚴格 JSON。只用標準函式庫，供發布器與唯讀存取共用。

GitHub REST transport and fixed diagnostic codes.

Call budget, deadline, response size limit, token destination, no redirects and
strict JSON. Standard library only, shared by the publisher and read-only access.
"""
import json
import math
import re
import time
import urllib.error
import urllib.parse
import urllib.request

API_CALL_BUDGET = 600
API_SECONDS = 240


class Denied(ValueError):
    """發布器只輸出固定診斷碼。

Only fixed diagnostic codes may leave the publisher."""


def need(condition, code):
    if not condition:
        raise Denied(code)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def constant(_):
        raise Denied("NONFINITE_JSON")
    def finite(raw):
        value = float(raw)
        need(math.isfinite(value), "NONFINITE_JSON")
        return value
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    def __init__(self, token):
        self.token = token
        self.calls = 0
        self.publish_reserved_used = False
        self.deadline = time.monotonic() + API_SECONDS
        self.opener = urllib.request.build_opener(NoRedirect())

    def raw(self, url, method="GET", payload=None, authenticated=True, limit=2 * 1024**2):
        parsed = urllib.parse.urlsplit(url)
        need(parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port in (None, 443), "API_URL")
        need(not authenticated or parsed.netloc == "api.github.com", "AUTH_DESTINATION")
        # 驗證預算用完後仍保留一次發布結果的呼叫，才能以 failure 取代舊綠燈。 / One result-publishing call stays
        # reserved after verification spends the budget, so a failure can still replace an earlier green.
        reserved = (method == "POST" and not self.publish_reserved_used
                    and re.fullmatch(r"https://api\.github\.com/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/check-runs", url))
        if reserved:
            self.publish_reserved_used = True
        else:
            self.calls += 1
            need(self.calls <= API_CALL_BUDGET and time.monotonic() < self.deadline, "API_BUDGET")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        if payload is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, headers=headers, method=method,
                                     data=None if payload is None else json.dumps(payload).encode())
        try:
            timeout = 20 if reserved else min(20, max(1, self.deadline-time.monotonic()))
            with self.opener.open(req, timeout=timeout) as response:
                data = response.read(limit + 1)
                need(len(data) <= limit, "API_RESPONSE_LIMIT")
                return data
        except urllib.error.HTTPError as exc:
            if exc.code == 302 and authenticated and method == "GET" and re.fullmatch(
                    r"https://api.github.com/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/artifacts/[0-9]+/zip", url):
                location = exc.headers.get("Location", "")
                host = urllib.parse.urlsplit(location).hostname or ""
                need(host.endswith(".blob.core.windows.net"), "ARTIFACT_REDIRECT_HOST")
                # Installation／JWT 憑證不可跟隨儲存服務重新導向。 / Installation/JWT credentials must never follow storage redirects.
                return self.raw(location, authenticated=False, limit=limit)
            if exc.code in (403, 429) and (exc.code == 429 or exc.headers.get("Retry-After")
                    or exc.headers.get("X-RateLimit-Remaining") == "0"):
                raise Denied("GITHUB_RATE_LIMIT") from None
            raise Denied("GITHUB_HTTP_" + str(exc.code)) from None

    def api(self, path, method="GET", payload=None):
        need(path.startswith("/") and not path.startswith("//"), "API_PATH")
        return strict_json(self.raw("https://api.github.com" + path, method, payload))
