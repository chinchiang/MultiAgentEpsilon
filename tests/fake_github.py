"""記憶體假 GitHub 傳輸層：依路徑與查詢回應並照 GitHub 規則分頁，另模擬 workflow 重跑，供 reader 測試使用。 / In-memory
fake GitHub transport that answers by path and query, paginates the way GitHub does and models workflow reruns, for
reader tests."""
import json
import urllib.parse

from security_harness.github_http import Denied, strict_json

PAGING = ("per_page", "page")
ACTIONS_APP_ID = 15368


class FakeGitHub:
    def __init__(self, repo="owner/repo"):
        self.repo = repo
        self.prefix = f"/repos/{repo}/"
        self.routes = {}
        self.requests = []
        self.posts = []
        self.next_job_id = 1000

    def post_reply(self, path, payload):
        raise Denied("GITHUB_HTTP_404")

    def add(self, path, value):
        self.routes[route(self.prefix + path)] = value

    def listing(self, path, key, items, total_count=None):
        """帶 total_count 的物件列表；total_count 預設為實際筆數，也可指定成不符。 / An object listing with total_count,
        the actual item count unless set to disagree."""
        self.routes[route(self.prefix + path)] = Listing(key, items, total_count)

    def workflow_run(self, run_id, head_sha, check_suite_id, **fields):
        """一個 run 屬於一個 check suite，重跑仍沿用同一個；fields 補上事件、路徑等其他欄位。 / A run belongs to one
        check suite, kept across reruns; fields supply the event, path and anything else."""
        run = {"id": run_id, "head_sha": head_sha, "check_suite_id": check_suite_id, "run_attempt": 0,
               "status": "queued", "conclusion": None, **fields}
        self.add(f"actions/runs/{run_id}", run)
        suite = route(self.prefix + f"actions/runs?check_suite_id={check_suite_id}")
        self.routes.setdefault(suite, Listing("workflow_runs", [], None)).items.append(run)
        return run

    def attempt(self, run, conclusion="success", name="trusted-security-evaluation"):
        """run 前進到下一個 attempt 並產生該 attempt 的 job；回傳對應的 check run，其 id 等於 job id。 / Advance the run to
        its next attempt with that attempt's own job, and return the matching check run, whose id is the job id."""
        run["run_attempt"] += 1
        run.update(status="completed", conclusion=conclusion)
        job_id, self.next_job_id = self.next_job_id, self.next_job_id + 1
        self.add(f"actions/jobs/{job_id}", {
            "id": job_id, "run_id": run["id"], "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
            "name": name, "status": "completed", "conclusion": conclusion,
            "check_run_url": f"https://api.github.com/repos/{self.repo}/check-runs/{job_id}"})
        check = {"id": job_id, "name": name, "head_sha": run["head_sha"], "status": "completed",
                 "conclusion": conclusion, "check_suite": {"id": run["check_suite_id"]}, "app": {"id": ACTIONS_APP_ID}}
        self.check_runs(run["head_sha"], name).items.append(check)
        return check

    def check_runs(self, head_sha, name):
        """head 上指定名稱的所有 check run（filter=all）。 / Every check run of that name on the head (filter=all)."""
        path = route(self.prefix + f"commits/{head_sha}/check-runs?check_name={name}&filter=all")
        return self.routes.setdefault(path, Listing("check_runs", [], None))

    def api(self, path, method="GET", payload=None):
        """與 GitHub.api 相同：送出請求並嚴格解析 JSON。 / Same as GitHub.api: send the request and parse strict JSON."""
        return strict_json(self.raw("https://api.github.com" + path, method, payload))

    def job(self, job_id):
        return self.routes[route(self.prefix + f"actions/jobs/{job_id}")]

    def raw(self, url, method="GET", payload=None, authenticated=True, limit=2 * 1024**2):
        parts = urllib.parse.urlsplit(url)
        assert (parts.scheme, parts.netloc) == ("https", "api.github.com"), url
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True, strict_parsing=bool(parts.query))
        # 重複參數在 GitHub 上靜默生效，這裡直接讓測試失敗。 / GitHub silently accepts repeated parameters; fail the test instead.
        assert len({name for name, _ in query}) == len(query), f"repeated query parameter: {url}"
        self.requests.append((method, parts.path, dict(query)))
        if method == "POST":
            # 記錄寫入，回應由測試指定。 / Record the write; the test decides the reply.
            self.posts.append((parts.path, json.loads(json.dumps(payload))))
            return json.dumps(self.post_reply(parts.path, payload)).encode()
        key = route(parts.path, query)
        if key not in self.routes:
            raise Denied("GITHUB_HTTP_404")
        value = self.routes[key]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, bytes):
            return value
        size = min(int(dict(query).get("per_page", 30)), 100)
        start = (int(dict(query).get("page", 1)) - 1) * size
        if isinstance(value, Listing):
            total = len(value.items) if value.total_count is None else value.total_count
            value = {"total_count": total, value.key: value.items[start:start + size]}
        elif isinstance(value, list):
            value = value[start:start + size]
        return json.dumps(value).encode()


class Listing:
    def __init__(self, key, items, total_count):
        self.key, self.items, self.total_count = key, items, total_count


def route(path, query=None):
    """路由以路徑加上排序後的非分頁參數為鍵。 / Routes are keyed by path plus the sorted non-paging parameters."""
    if query is None:
        path, _, raw = path.partition("?")
        query = urllib.parse.parse_qsl(raw, keep_blank_values=True)
    rest = sorted((name, value) for name, value in query if name not in PAGING)
    return path + ("?" + urllib.parse.urlencode(rest) if rest else "")
