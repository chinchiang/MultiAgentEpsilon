"""共同 GitHub 信任規則與完整證據蒐集；不取得憑證、不發布檢查。 / Shared GitHub trust rules and complete
 evidence collection; no credential acquisition or check publication."""
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from .github_http import Denied, need

# 共用 App 身分不能單獨證明 check 來源。 / The shared App identity alone does not prove a check's source.
GITHUB_ACTIONS_APP_ID = 15368
PR_COMMIT_LIMIT = 250


def validate_review(pr, reviews, permissions, settings, excluded):
    """excluded 包含接觸 head 的 run actor 與提交作者／提交者；這些自報或事件範圍身分只能移除核准，真實推送者仍以規則集原生最後推送核准為準。

excluded: identities that touched the head (run actors, commit author/committer).
    They are self-asserted or event-scoped, so they may only remove approvals; the
    ruleset's native last-push approval stays authoritative for the actual pusher."""
    latest = {}
    ids = set()
    for review in sorted(reviews, key=lambda r: r["id"]):
        need(type(review["id"]) is int and review["id"] not in ids, "REVIEW_ID")
        ids.add(review["id"])
        if review["state"] in ("APPROVED", "DISMISSED", "CHANGES_REQUESTED"):
            latest[review["user"]["login"]] = review
    allowed = []
    for login in [login for login in latest if is_bot(login)]:
        # bot 不是可查權限的協作者，也不會出現在審查者名單；它要求修改時仍阻擋。 / A bot is no collaborator whose
        # permission can be read and never a listed reviewer; its change request still blocks.
        need(latest.pop(login)["state"] != "CHANGES_REQUESTED", "CHANGES_REQUESTED")
    for login, review in latest.items():
        role = permissions.get(login)
        need(role in ("read", "triage", "write", "maintain", "admin"), "REVIEW_PERMISSION_UNKNOWN")
        capable = role in ("write", "maintain", "admin")
        need(not (capable and review["state"] == "CHANGES_REQUESTED"), "CHANGES_REQUESTED")
        if (login in settings["reviewers"] and login != pr["user"]["login"] and login not in excluded
                and capable and review["state"] == "APPROVED" and review["commit_id"] == pr["head"]["sha"]):
            allowed.append(review["id"])
    need(bool(allowed), "INDEPENDENT_APPROVAL_MISSING")
    return allowed


def is_bot(login):
    return isinstance(login, str) and login.endswith("[bot]")


def identities(*people):
    return {p["login"] for p in people if isinstance(p, dict) and isinstance(p.get("login"), str)}


def head_scope(pr):
    head = pr["head"]
    return head.get("sha"), (head.get("repo") or {}).get("id"), head.get("ref")


def run_scope(run):
    return run.get("head_sha"), (run.get("head_repository") or {}).get("id"), run.get("head_branch")


def related_pull_path(prefix, pr):
    repo = (pr["head"].get("repo") or {}).get("full_name", "")
    need(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo), "PR_HEAD_REPOSITORY")
    owner = repo.split("/")[0]
    return prefix + "/pulls?state=all&head=" + urllib.parse.quote(owner + ":" + pr["head"]["ref"], safe="")


def run_base_history(reader, pr, pulls):
    return {p["number"]: reader.items(f"issues/{p['number']}/timeline")
            for p in pulls if head_scope(p) == head_scope(pr)}


def validate_run_base(run, pr, pull_requests, base_branch, histories=None):
    """不信任 run 自報證據，將 pull_request_target 綁定此 PR 的 base。現況不能證明歷史 workflow；相同 head／repo／branch 曾改 base 即拒絕，包括來回切換與重跑，時間戳不能證明排隊事件來源。可用新 head 分支開新 PR，timeline 必須是完整 API 資料。

Bind a pull_request_target run to this PR's base without trusting run evidence.

    Current PR state cannot prove historical workflow source. Without a signed
    source identity, any base-retargeted PR sharing this exact head/repo/branch is
    refused, including later reruns and retarget-away-and-back. Creation timestamps
    alone cannot establish which queued event supplied a workflow. A new PR on a
    new head branch can be evaluated normally. Timelines must be complete API data.
    """
    head = pr["head"]["sha"]
    need(run.get("head_sha") == head, "RUN_SHA")
    head_repo = (pr["head"].get("repo") or {}).get("id")
    need(head_repo is not None and run.get("head_branch") == pr["head"].get("ref")
         and (run.get("head_repository") or {}).get("id") == head_repo, "RUN_HEAD_BRANCH")
    need(isinstance(pull_requests, list) and any(p.get("number") == pr["number"] for p in pull_requests),
         "PR_LISTING_INCOMPLETE")
    relevant = [p for p in pull_requests if head_scope(p) == head_scope(pr)]
    need(any(p["number"] == pr["number"] for p in relevant), "PR_LISTING_INCOMPLETE")
    need(all(p["base"]["ref"] == base_branch and p["base"]["repo"]["id"] == pr["base"]["repo"]["id"]
             for p in relevant), "FOREIGN_BASE_PR")
    need(isinstance(histories, dict), "BASE_HISTORY_MISSING")
    for p in relevant:
        events = histories.get(p["number"])
        need(isinstance(events, list) and all(isinstance(e, dict) and isinstance(e.get("event"), str)
                                             for e in events), "BASE_HISTORY_MISSING")
        need(not any(e["event"] == "base_ref_changed" for e in events), "BASE_RETARGETED_UNVERIFIABLE")
    # 關聯 PR 快照若存在，只能進一步限縮信任。 / Associated PR snapshots, when present, may only constrain trust further.
    for linked in run.get("pull_requests", []):
        if linked.get("number") == pr["number"] and linked.get("base"):
            need(linked["base"].get("ref") == base_branch, "RUN_ORIGINAL_BASE")


def pr_commit_identities(commits, head):
    """GitHub 歸屬於任一 PR commit 的帳號屬自報資料，只用來排除核准；曾提交先前 commit 的審查者不獨立。

Accounts GitHub attributes any PR commit to. Self-asserted, so only ever used to
    exclude approvers: a reviewer who pushed earlier commits is not independent."""
    need(isinstance(commits, list) and 0 < len(commits) < PR_COMMIT_LIMIT, "PR_COMMITS_TRUNCATED")
    need(all(isinstance(c, dict) for c in commits) and commits[-1].get("sha") == head, "PR_COMMITS_HEAD")
    return set().union(*(identities(c.get("author"), c.get("committer")) for c in commits))


def approved_review(pr, reviews, head, base, reviewers, permissions, excluded=(), refusals=None):
    """只採計清單內具寫入權限、非作者或已知推送者的核准；排除名單只能移除核准，不能新增授權。

An approval counts only from a listed, write-capable reviewer who is not the
    author or a known pusher. Exclusions may only remove approvals, never add them."""
    if pr["state"] != "open" or pr["head"]["sha"] != head or pr["base"]["sha"] != base:
        return None
    try:
        ids = validate_review(pr, reviews, permissions, {"reviewers": reviewers}, set(excluded))
    except Denied as exc:
        # 沒有核准仍回傳 None，但留下固定診斷碼，讓證據說明為何擋下。 / No approval still returns None, but the fixed
        # diagnostic code is kept so the evidence says why it blocked.
        if refusals is not None:
            refusals.append(str(exc))
        return None
    review = next(r for r in reviews if r["id"] == ids[0])
    return {"review_id": review["id"], "reviewer": review["user"]["login"], "commit_id": head}


def parse_time(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class ReviewEvidence:
    reviews: list
    permissions: dict
    commit_identities: set


class RunBaseEvidence:
    """單次命令內重用的來源證據，不是跨請求原子快照。 / Source evidence reused within one command, not an atomic snapshot."""

    def __init__(self, pr, pulls, base_branch, histories):
        self._pr, self._pulls = pr, pulls
        self._base_branch, self._histories = base_branch, histories

    def validate(self, run):
        validate_run_base(run, self._pr, self._pulls, self._base_branch, self._histories)


class GitHubTrust:
    """在既有 reader 上組合信任證據；每次呼叫都重新讀取。 / Compose trust evidence over the existing reader;
    each call reads fresh evidence."""

    def __init__(self, reader):
        self._reader = reader

    def _permissions(self, reviews):
        logins = {r['user']['login'] for r in reviews
                  if r['state'] in ('APPROVED', 'DISMISSED', 'CHANGES_REQUESTED') and not is_bot(r['user']['login'])}
        return {login: self._reader.get(f"collaborators/{urllib.parse.quote(login, safe='')}/permission")['role_name']
                for login in logins}

    def _commit_identities(self, number, head):
        commit = self._reader.get(f'commits/{head}')
        return (identities(commit.get('author'), commit.get('committer'))
                | pr_commit_identities(self._reader.items(f'pulls/{number}/commits'), head))

    def _related_pulls(self, pr):
        return self._reader.items(related_pull_path('', pr).lstrip('/'))

    def run_base(self, pr, base_branch):
        pulls = self._related_pulls(pr)
        return RunBaseEvidence(pr, pulls, base_branch, run_base_history(self._reader, pr, pulls))

    def publication_review(self, number, pr, run, base_branch):
        """蒐集發布前的審查證據，先驗證唯一 PR 與來源，再讀提交身分。 / Collect publication review evidence:
        verify the unique PR and source before reading commit identities."""
        reviews = self._reader.items(f'pulls/{number}/reviews')
        permissions = self._permissions(reviews)
        pulls = self._related_pulls(pr)
        need([p['number'] for p in pulls if p['state'] == 'open' and head_scope(p) == head_scope(pr)] == [number],
             'SHARED_PR_HEAD')
        validate_run_base(run, pr, pulls, base_branch, run_base_history(self._reader, pr, pulls))
        return ReviewEvidence(reviews, permissions, self._commit_identities(number, pr['head']['sha']))

    def review_ids(self, number, pr, reviewers, excluded):
        """發布前重讀審查與權限，沿用已核對的排除身分。 / Reread reviews and permissions before publication,
        retaining the previously verified excluded identities."""
        reviews = self._reader.items(f"pulls/{number}/reviews")
        return validate_review(pr, reviews, self._permissions(reviews), {'reviewers': reviewers}, excluded)

    def baseline_approval(self, number, head, base, reviewers, run_id=None, refusals=None):
        reader = self._reader
        pr = reader.get(f"pulls/{number}")
        # fork 的分支不在 base repo 的 activity 裡，無法確認推送時間與推送者；明確拒絕。 / A fork's branch is not in the
        # base repository's activity, so its push time and pusher cannot be established; refuse explicitly.
        if (pr["head"].get("repo") or {}).get("id") != (pr["base"].get("repo") or {}).get("id"):
            raise Denied("FORK_PR_UNSUPPORTED")
        # 提交身分可自報，真正擋下審查者自我核准的是規則集的最後推送核准；規則被關掉時不得放行。 / Commit identities
        # are self-asserted, so the ruleset's last-push approval is what stops self-approval; refuse when it is off.
        rules = reader.items("rules/branches/main")
        if not any(rule.get("type") == "pull_request" and isinstance(rule.get("parameters"), dict)
                   and rule["parameters"].get("require_last_push_approval") is True for rule in rules):
            raise Denied("LAST_PUSH_APPROVAL")
        reviews = reader.items(f"pulls/{number}/reviews")
        # 只合併 base 的推送不會讓核准失效，GitHub 還會把 commit_id 改指新 head；改以伺服器記錄的推送時間判定。
        # / A base-only push keeps approvals and GitHub re-points their commit_id; judge by the server-recorded push time.
        ref = pr["head"]["ref"]
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", ref):
            raise Denied("HEAD_REF")
        # activity 以 cursor 分頁、忽略 page，只讀由新到舊的第一頁。每筆 activity 都會移動分支，head 未變時最新一筆就是
        # head 的推送；不在第一頁即視為不明。 / Activity is cursor-paged and ignores page, so read only the newest-first
        # first page. Every activity moves the branch, so while the head is unchanged the newest one is the head push;
        # a head push beyond the first page counts as unknown.
        head_pushes = [a for a in reader.get(f"activity?ref=refs/heads/{ref}&direction=desc") if a.get("after") == head]
        if not head_pushes:
            raise Denied("LAST_PUSH_UNKNOWN")
        pushed = max(parse_time(a["timestamp"]) for a in head_pushes)
        reviews = [{**r, "state": "DISMISSED"} if r["state"] == "APPROVED" and parse_time(r["submitted_at"]) <= pushed
                   else r for r in reviews]
        candidates = {r["user"]["login"] for r in reviews
                      if r["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED")}
        permissions = {}
        for login in sorted(candidates):
            if not re.fullmatch(r"[A-Za-z0-9-]+", login):
                continue
            permissions[login] = reader.get(f"collaborators/{login}/permission")["role_name"]
        # 提交身分可自報，因此只能排除審查者， / Commit identities are self-asserted, so they are used only to exclude reviewers;
        # 真實推送者仍由規則集原生最後推送核准檢查判定。 / the ruleset's native last-push approval remains the authoritative pusher check.
        # 伺服器記錄的 head 推送者不能核准；改標題、重開或按重跑的人只是 run actor，不是推送者，核准仍有效。 / The
        # server-recorded pusher of the head cannot approve. Whoever edited the title, reopened or re-ran is only a run
        # actor, not a pusher, and their approval still counts.
        excluded = self._commit_identities(number, head) | identities(*(a.get("actor") for a in head_pushes))
        if run_id:
            if not re.fullmatch(r"[1-9][0-9]*", run_id):
                raise ValueError("invalid run identity")
            run = reader.get(f"actions/runs/{run_id}")
            self.run_base(pr, "main").validate(run)
        return approved_review(pr, reviews, head, base, reviewers, permissions, excluded, refusals)
