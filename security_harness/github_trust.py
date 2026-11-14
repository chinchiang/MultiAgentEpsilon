"""共同 GitHub 信任規則與完整證據蒐集；不取得憑證、不發布檢查。 / Shared GitHub trust rules and complete
 evidence collection; no credential acquisition or check publication."""
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

from .github_http import Denied, need
from .workflow_contract import BASE_BRANCH

# 共用 App 身分不能單獨證明 check 來源。 / The shared App identity alone does not prove a check's source.
GITHUB_ACTIONS_APP_ID = 15368
PR_COMMIT_LIMIT = 250


def validate_review(pr, reviews, permissions, settings, excluded):
    """excluded 包含 PR 提交身分（作者／提交者）與伺服器 activity 記錄的分支推送者；這些身分只能移除核准，真實推送者仍以規則集原生最後推送核准為準。

excluded: the PR's commit identities (author/committer) and the branch pushers the
    server's activity records. They may only remove approvals; the ruleset's native
    last-push approval stays authoritative for the actual pusher."""
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


def trusted_run(run, head_sha, repository, workflow_path, workflow_id=None):
    """這個 run 是否來自可信 workflow 對此 head 的 pull_request_target；verifier 與發布程式共用。各項依序檢查，拒絕碼
    指出哪一項不符。 / Whether this run is the trusted workflow's pull_request_target run for this head, shared by the
    verifier and the publisher. Each check runs in turn and its refusal code names the one that failed."""
    need((run.get("repository") or {}).get("full_name") == repository, "RUN_REPOSITORY")
    need(run.get("event") == "pull_request_target" and run.get("path") == workflow_path
         and (workflow_id is None or run.get("workflow_id") == workflow_id), "RUN_SOURCE")
    need(run.get("head_sha") == head_sha, "RUN_SHA")


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


def approved_review(pr, reviews, head, base, reviewers, permissions, excluded, push, refusals=None):
    """只採計清單內具寫入權限、非作者或已知推送者的核准；排除名單只能移除核准，不能新增授權。

An approval counts only from a listed, write-capable reviewer who is not the
    author or a known pusher. Exclusions may only remove approvals, never add them."""
    # PR 已關閉或在讀取期間移動時沒有核准可用；留下固定診斷碼。 / A closed PR, or one that moved while it was read, has no
    # usable approval; leave a fixed diagnostic code.
    stale = ("PR_NOT_OPEN" if pr["state"] != "open" else "PR_HEAD_MOVED" if pr["head"]["sha"] != head
             else "PR_BASE_MOVED" if pr["base"]["sha"] != base else None)
    if stale:
        if refusals is not None:
            refusals.append(stale)
        return None
    try:
        ids = review_decision(pr, reviews, permissions, reviewers, excluded, push)
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
class HeadPush:
    """伺服器記錄的 head 推送：時間與推送者。 / The server-recorded push of the head: its time and pushers."""
    pushed: datetime
    pushers: frozenset


def review_decision(pr, reviews, permissions, reviewers, excluded, push):
    """guard 與 publisher 共用的唯一審查規則：PR 須非 draft；head 推送當下或之前送出的核准視為 DISMISSED（只合併 base
    的推送不會讓核准失效，GitHub 還會把 commit_id 改指新 head）；head 推送者與提交身分都不能核准。

The one review rule shared by the guard and the publisher: the PR must not be a draft; an approval submitted at or
    before the head push counts as DISMISSED (a base-only push keeps approvals and GitHub re-points their commit_id);
    neither the head pusher nor any commit identity can approve."""
    need(pr.get("draft") is False, "PR_NOT_REVIEWABLE")
    need(isinstance(push, HeadPush), "LAST_PUSH_UNKNOWN")
    reviews = [{**r, "state": "DISMISSED"} if r["state"] == "APPROVED" and parse_time(r["submitted_at"]) <= push.pushed
               else r for r in reviews]
    return validate_review(pr, reviews, permissions, {"reviewers": reviewers}, set(excluded) | push.pushers)


@dataclass(frozen=True)
class ReviewEvidence:
    reviews: list
    permissions: dict
    commit_identities: set
    push: HeadPush


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

    def head_push(self, number, pr, base_branch):
        """讀出 head 的推送時間與推送者，並拒絕 fork、共用 head、規則集未要求最後推送核准與無法確認的推送。

Read the head's push time and pushers; refuse a fork, a shared head, a ruleset that does not require last-push
        approval and a push that cannot be established."""
        # fork 的分支不在 base repo 的 activity 裡，無法確認推送時間與推送者；明確拒絕。 / A fork's branch is not in the
        # base repository's activity, so its push time and pusher cannot be established; refuse explicitly.
        if (pr["head"].get("repo") or {}).get("id") != (pr["base"].get("repo") or {}).get("id"):
            raise Denied("FORK_PR_UNSUPPORTED")
        ref = pr["head"]["ref"]
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", ref):
            raise Denied("HEAD_REF")
        pulls = self._related_pulls(pr)
        need([p["number"] for p in pulls if p["state"] == "open" and head_scope(p) == head_scope(pr)] == [number],
             "SHARED_PR_HEAD")
        # 提交身分可自報，真正擋下審查者自我核准的是規則集的最後推送核准；規則被關掉時不得放行。 / Commit identities
        # are self-asserted, so the ruleset's last-push approval is what stops self-approval; refuse when it is off.
        need(re.fullmatch(r"[A-Za-z0-9._/-]+", base_branch), "BASE_BRANCH")
        rules = self._reader.items(f"rules/branches/{base_branch}")
        if not any(rule.get("type") == "pull_request" and isinstance(rule.get("parameters"), dict)
                   and rule["parameters"].get("require_last_push_approval") is True for rule in rules):
            raise Denied("LAST_PUSH_APPROVAL")
        # activity 以 cursor 分頁、忽略 page，只讀由新到舊的第一頁。每筆 activity 都會移動分支，head 未變時最新一筆必須
        # 就是 head 的推送；不是就表示分支已移走，推送時間視為不明。 / Activity is cursor-paged and ignores page, so read
        # only the newest-first first page. Every activity moves the branch, so while the head is unchanged the newest
        # one must be the head push; otherwise the branch has moved on and the push time counts as unknown.
        head = pr["head"]["sha"]
        page = self._reader.get(f"activity?ref=refs/heads/{ref}&direction=desc")
        if not page or page[0].get("after") != head:
            raise Denied("LAST_PUSH_UNKNOWN")
        head_pushes = [a for a in page if a.get("after") == head]
        # 第一頁上所有推送這個分支的伺服器記錄身分都不能核准，包含較早 commit 的推送者；commit 名義可自報，不能單獨
        # 依賴。改標題、重開或按重跑的人只是 run actor，不是推送者，核准仍有效。 / Every server-recorded identity that
        # pushed this branch on the first page is excluded, including whoever pushed an earlier commit, because commit
        # names are self-asserted. Whoever edited the title, reopened or re-ran is only a run actor, not a pusher, and
        # their approval still counts.
        return HeadPush(max(parse_time(a["timestamp"]) for a in head_pushes),
                        frozenset(identities(*(a.get("actor") for a in page))))

    def publication_review(self, number, pr, run, base_branch):
        """蒐集發布前的審查證據，先驗證唯一 PR、推送與來源，再讀提交身分。 / Collect publication review evidence:
        verify the unique PR, the push and the source before reading commit identities."""
        push = self.head_push(number, pr, base_branch)
        reviews = self._reader.items(f'pulls/{number}/reviews')
        permissions = self._permissions(reviews)
        pulls = self._related_pulls(pr)
        validate_run_base(run, pr, pulls, base_branch, run_base_history(self._reader, pr, pulls))
        return ReviewEvidence(reviews, permissions, self._commit_identities(number, pr['head']['sha']), push)

    def review_ids(self, number, pr, reviewers, excluded, base_branch):
        """發布前重讀推送、審查與權限，沿用已核對的提交身分。 / Reread the push, reviews and permissions before
        publication, retaining the previously verified commit identities."""
        push = self.head_push(number, pr, base_branch)
        reviews = self._reader.items(f"pulls/{number}/reviews")
        return review_decision(pr, reviews, self._permissions(reviews), reviewers, excluded, push)

    def baseline_approval(self, number, head, base, reviewers, run_id=None, refusals=None, base_branch=BASE_BRANCH):
        pr = self._reader.get(f"pulls/{number}")
        push = self.head_push(number, pr, base_branch)
        reviews = self._reader.items(f"pulls/{number}/reviews")
        # 提交身分可自報，因此只能排除審查者， / Commit identities are self-asserted, so they are used only to exclude reviewers;
        # 真實推送者仍由規則集原生最後推送核准檢查判定。 / the ruleset's native last-push approval remains the authoritative pusher check.
        excluded = self._commit_identities(number, head)
        if run_id:
            if not re.fullmatch(r"[1-9][0-9]*", run_id):
                raise ValueError("invalid run identity")
            run = self._reader.get(f"actions/runs/{run_id}")
            self.run_base(pr, base_branch).validate(run)
        return approved_review(pr, reviews, head, base, reviewers, self._permissions(reviews), excluded, push, refusals)
