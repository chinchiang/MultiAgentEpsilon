from scripts.check_trusted_changes import protected_changes
from scripts.check_trusted_changes import approved_review
import json
import subprocess
import sys
import pytest
from pathlib import Path

from tests.fake_github import FakeGitHub

# 目前 main 規則集套用的最後推送核准規則。 / The last-push approval rule the main ruleset currently applies.
PULL_REQUEST_RULE = {"type": "pull_request", "ruleset_id": 1, "parameters": {"require_last_push_approval": True}}
PULL = {"state": "open", "head": {"sha": "h" * 40, "ref": "feature"}, "base": {"sha": "b" * 40},
        "user": {"login": "someone-else"}}
# GitHub 伺服器記錄的推送；commit 日期可自報，不能代表推送時間。 / A server-recorded push; commit dates are self-asserted.
HEAD_PUSH = {"activity_type": "push", "before": "e" * 40, "after": "h" * 40, "timestamp": "2026-10-13T07:00:09Z"}
POLICY = json.loads((Path(__file__).resolve().parents[1] / "security/trust-policy.json").read_text())
REVIEWER = POLICY["baseline_reviewers"][-1]


@pytest.fixture(autouse=True)
def clear_ci_run_identity(monkeypatch):
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)


class Candidate:
    """已初始化、尚無 commit 的合成候選 repo。 / A synthetic candidate repository, initialized with no commits yet."""

    def __init__(self, path):
        self.path = path
        path.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic fixture")
        self.git("config", "user.email", "fixture@example.invalid")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.path), *args], text=True).strip()

    def commit(self, files, message):
        """寫入檔案並提交，回傳新 commit。 / Write the files, commit them and return the new commit."""
        for name, content in files.items():
            (self.path / name).parent.mkdir(parents=True, exist_ok=True)
            (self.path / name).write_text(content)
        self.git("add", ".")
        self.git("commit", "-qm", message)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def candidate(tmp_path):
    return Candidate(tmp_path / "candidate")


def test_candidate_cannot_silently_lower_policy_or_replace_evaluator():
    paths = ["security/policy.json", "security/gitleaks.toml", "scripts/run_security.py",
             "security_harness/results.py", ".github/workflows/security.yml",
             "requirements.lock", "fixture_app/app.py", "docs/README.md"]
    assert protected_changes(paths) == paths


def test_new_execution_entrypoints_are_protected_by_default():
    paths = ["conftest.py", "pytest.py", "sitecustomize.py", ".gitleaksignore", ".gitignore", "new_runner.py"]
    assert protected_changes(paths) == paths


def test_baseline_approval_binds_independent_reviewer_and_current_head():
    pr = {"state": "open", "head": {"sha": "head"}, "base": {"sha": "base"}, "user": {"login": "author"}}
    review = {"id": 1, "state": "APPROVED", "commit_id": "head", "user": {"login": "owner"}}
    write = {"owner": "write", "author": "admin"}
    assert approved_review(pr, [review], "head", "base", ["owner"], write)["review_id"] == 1
    assert approved_review(pr, [review], "changed", "base", ["owner"], write) is None
    assert approved_review(pr, [review], "head", "new-base", ["owner"], write) is None
    assert approved_review(pr, [review], "head", "base", ["stranger"], write) is None
    assert approved_review(pr, [{**review, "user": {"login": "author"}}], "head", "base", ["author"], write) is None
    assert approved_review(pr, [review, {**review, "id": 2, "state": "DISMISSED"}], "head", "base", ["owner"], write) is None


@pytest.mark.parametrize("role", ["read", "triage", None, "custom"])
def test_listed_reviewer_without_write_access_cannot_approve_baseline(role):
    # GitHub 也記錄唯讀者核准；這些不能解除 guard。 / GitHub records approvals from read-only users; they must not lift the guard.
    pr = {"state": "open", "head": {"sha": "head"}, "base": {"sha": "base"}, "user": {"login": "author"}}
    review = {"id": 1, "state": "APPROVED", "commit_id": "head", "user": {"login": "owner"}}
    assert approved_review(pr, [review], "head", "base", ["owner"], {"owner": role}) is None
    assert approved_review(pr, [review], "head", "base", ["owner"], {"owner": "maintain"})["reviewer"] == "owner"


def test_head_commit_identities_only_remove_approvals():
    pr = {"state": "open", "head": {"sha": "head"}, "base": {"sha": "base"}, "user": {"login": "author"}}
    review = {"id": 1, "state": "APPROVED", "commit_id": "head", "user": {"login": "owner"}}
    assert approved_review(pr, [review], "head", "base", ["owner"], {"owner": "write"}, {"owner"}) is None
    assert approved_review(pr, [review], "head", "base", ["owner"], {"owner": "write"}, {"web-flow"}) is not None


def head_commit_only(_reviewer):
    # PR 只有 head commit，作者與提交者都不是審查者。 / The PR holds only the head commit, by someone other than the reviewer.
    return [{"sha": "h" * 40, "author": {"login": "someone-else"}, "committer": {"login": "web-flow"}}]


def guarded_repository(monkeypatch, commits=head_commit_only, role="write", rules=None,
                       submitted="2026-10-13T07:02:12Z", activity=None):
    """guard 讀到的 GitHub：PR 7 有一筆名單內審查者的核准。回傳假 GitHub 與對 PR 7 執行 live_approval 的函式。 / The
    GitHub state the guard reads: PR 7 carries one approval from a listed reviewer. Returns the fake GitHub and a
    function that runs live_approval on PR 7."""
    import scripts.check_trusted_changes as guard
    github = FakeGitHub(POLICY["repository"])
    github.add("pulls/7", PULL)
    github.add(f"collaborators/{REVIEWER}/permission", {"role_name": role})
    github.add("commits/" + "h" * 40, {"author": {"login": "someone-else"}, "committer": {"login": "web-flow"}})
    github.add("pulls/7/reviews", [{"id": 3, "state": "APPROVED", "commit_id": "h" * 40, "user": {"login": REVIEWER},
                                    "submitted_at": submitted}])
    github.add("pulls/7/commits", commits(REVIEWER))
    github.add("rules/branches/main", rules if rules is not None else [PULL_REQUEST_RULE])
    github.cursor_listing("activity?ref=refs/heads/feature", activity if activity is not None else [HEAD_PUSH])
    monkeypatch.setattr(guard, "ReadOnlyGitHub", lambda: github)
    return github, lambda: guard.live_approval(7, "h" * 40, "b" * 40)


@pytest.mark.parametrize("role,approved", [("write", True), ("read", False)])
def test_live_approval_resolves_reviewer_permission_through_github(monkeypatch, role, approved):
    github, approve = guarded_repository(monkeypatch, role=role)
    assert (approve() is not None) is approved
    assert any(path.endswith(f"/collaborators/{REVIEWER}/permission") for _, path, _ in github.requests)
    assert {method for method, _, _ in github.requests} == {"GET"}


def test_guard_retains_sha_bound_evidence_even_when_it_blocks(tmp_path, candidate):
    base = candidate.commit({"README.md": "baseline\n"}, "baseline")
    output = tmp_path / "audit/trusted-guard.json"
    script = Path(__file__).resolve().parents[1] / "scripts/check_trusted_changes.py"
    command = [sys.executable, str(script), "--base", base, "--candidate", str(candidate.path), "--output", str(output)]
    allowed = subprocess.run(command, capture_output=True)
    assert allowed.returncode == 0
    assert json.loads(output.read_text())["decision"] == "ALLOW"
    head = candidate.commit({"security/policy.json": "{}\n"}, "policy change")
    blocked = subprocess.run(command, capture_output=True)
    evidence = json.loads(output.read_text())
    assert blocked.returncode == 1
    assert evidence["decision"] == "BLOCK"
    assert evidence["base_sha"] == base
    assert evidence["candidate_sha"] == head
    assert evidence["protected_changes"] == ["security/policy.json"]


@pytest.mark.parametrize("old,new,blocked", [
    ("scripts/evaluator.py", "fixture_app/moved.py", True),
    ("fixture_app/app.py", "scripts/evaluator.py", True),
    ("fixture_app/app.py", "fixture_app/moved.py", True),
])
def test_git_rename_checks_both_sides(candidate, old, new, blocked):
    candidate.git("config", "diff.renames", "true")
    base = candidate.commit({old: "unchanged content\n"}, "base")
    (candidate.path / new).parent.mkdir(parents=True, exist_ok=True)
    candidate.git("mv", old, new); candidate.git("commit", "-qm", "rename")
    assert candidate.git("diff", "--name-status", base, "HEAD").startswith("R100")
    script = Path(__file__).resolve().parents[1] / "scripts/check_trusted_changes.py"
    process = subprocess.run([sys.executable, str(script), "--base", base, "--candidate", str(candidate.path)],
                             capture_output=True, text=True)
    data = json.loads(process.stdout)
    assert process.returncode == int(blocked)
    assert data["decision"] == ("BLOCK" if blocked else "ALLOW")
    assert data["protected_changes"] == protected_changes(sorted([old, new]))


@pytest.mark.parametrize("rules", [
    [{**PULL_REQUEST_RULE, "parameters": {"require_last_push_approval": False}}],
    [{**PULL_REQUEST_RULE, "parameters": {}}],
    [{"type": "deletion", "ruleset_id": 1}],
    [],
], ids=["disabled", "parameter-missing", "no-pull-request-rule", "no-rules"])
def test_valid_approval_is_refused_when_last_push_approval_is_not_enforced(monkeypatch, rules):
    # 審查者身分可偽造推送者，真正擋下的是規則集的最後推送核准；規則被關掉時不得放行。 / Commit identities are
    # self-asserted, so the ruleset's last-push approval is what really stops self-approval; refuse when it is off.
    from security_harness.trusted_publisher import Denied
    _, approve = guarded_repository(monkeypatch, rules=rules)
    with pytest.raises(Denied, match="^LAST_PUSH_APPROVAL$"):
        approve()


def test_approval_submitted_before_the_head_was_pushed_does_not_count(monkeypatch):
    # 只合併 base 的 update-branch 不會讓核准失效，GitHub 還把 commit_id 改指新 head。 / A base-only update-branch keeps
    # the approval and GitHub re-points its commit_id to the new head.
    _, approve = guarded_repository(monkeypatch, submitted="2026-10-13T06:44:15Z")
    assert approve() is None


@pytest.mark.parametrize("activity", [[], [{**HEAD_PUSH, "after": "e" * 40}]], ids=["no-activity", "other-head"])
def test_unknown_push_time_of_the_head_fails_closed(monkeypatch, activity):
    from security_harness.trusted_publisher import Denied
    _, approve = guarded_repository(monkeypatch, activity=activity)
    with pytest.raises(Denied, match="^LAST_PUSH_UNKNOWN$"):
        approve()


def other_pushes(count, day="2026-10-12"):
    # 當天推送其他 commit 的 activity，由新到舊。 / That day's pushes of other commits, newest first.
    return [{"activity_type": "push", "before": "e" * 40, "after": f"{n:040x}",
             "timestamp": f"{day}T{n // 60:02d}:{n % 60:02d}:00Z"} for n in range(count - 1, -1, -1)]


def test_long_branch_history_finds_the_head_push_in_one_read(monkeypatch):
    # activity 以 cursor 分頁、忽略 page；最新的 activity 就是 head 的推送。 / Activity is cursor-paged and ignores page;
    # the newest activity is the head push.
    github, approve = guarded_repository(monkeypatch, activity=[HEAD_PUSH, *other_pushes(149)])
    assert approve() is not None
    assert sum(path.endswith("/activity") for _, path, _ in github.requests) == 1


def test_head_push_beyond_the_newest_activity_page_fails_closed(monkeypatch):
    # head 推送之後還有 34 筆 activity，與 head 未變相矛盾；不翻舊頁，直接視為不明。 / Thirty-four activities after the
    # head push contradict an unchanged head; older pages are not read and the push time counts as unknown.
    from security_harness.trusted_publisher import Denied
    _, approve = guarded_repository(monkeypatch,
                                    activity=[*other_pushes(34, day="2026-10-14"), HEAD_PUSH, *other_pushes(5)])
    with pytest.raises(Denied, match="^LAST_PUSH_UNKNOWN$"):
        approve()


def test_reviewer_who_pushed_an_earlier_pr_commit_cannot_approve(monkeypatch):
    _, approve = guarded_repository(monkeypatch, lambda reviewer: [
        {"sha": "e" * 40, "author": {"login": reviewer}, "committer": {"login": reviewer}},
        {"sha": "h" * 40, "author": {"login": "someone-else"}, "committer": {"login": "web-flow"}}])
    assert approve() is None


@pytest.mark.parametrize("commits", [
    lambda reviewer: [],
    lambda reviewer: [{"sha": "e" * 40}],                                  # 清單不在 head 結束。 / list does not end at the head
    lambda reviewer: [{"sha": f"{i:040x}"} for i in range(249)] + [{"sha": "h" * 40}],  # API 在 250 筆截斷。 / API truncates at 250
])
def test_incomplete_pr_commit_listing_fails_closed(monkeypatch, commits):
    from security_harness.trusted_publisher import Denied
    with pytest.raises(Denied, match='^(?:PR_COMMITS_HEAD|PR_COMMITS_TRUNCATED)$'):
        guarded_repository(monkeypatch, commits)[1]()


@pytest.mark.parametrize("change", [{"require_independent_author": False}, {"require_independent_author": None},
                                    {"schema_version": 2}])
def test_guard_refuses_trust_policy_it_cannot_enforce(tmp_path, monkeypatch, change):
    import scripts.check_trusted_changes as guard
    policy = json.loads((Path(__file__).resolve().parents[1] / "security/trust-policy.json").read_text())
    (tmp_path / "security").mkdir()
    (tmp_path / "security/trust-policy.json").write_text(json.dumps({**policy, **change}))
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    monkeypatch.setattr(guard, "ReadOnlyGitHub", lambda: pytest.fail("GitHub must not be queried"))
    with pytest.raises(ValueError, match="unsupported trust policy"):
        guard.live_approval(7, "h" * 40, "b" * 40)


def run_guard_command(monkeypatch, tmp_path, candidate, github):
    import scripts.check_trusted_changes as guard
    base = candidate.commit({"README.md": "baseline\n"}, "baseline")
    output = tmp_path / "audit/trusted-guard.json"
    monkeypatch.setattr(guard, "ReadOnlyGitHub", lambda: github)
    monkeypatch.setattr("sys.argv", ["check_trusted_changes.py", "--base", base,
                                     "--candidate", str(candidate.path), "--pr", "7", "--output", str(output)])
    assert guard.main() == 1
    return json.loads(output.read_text())


def test_a_refused_github_read_is_recorded_with_its_code(monkeypatch, tmp_path, candidate):
    # 沒有 PR 7 可讀：記下拒絕碼，而不只是例外類型。 / PR 7 cannot be read: record the refusal code, not just the type.
    evidence = run_guard_command(monkeypatch, tmp_path, candidate, FakeGitHub(POLICY["repository"]))
    assert (evidence["decision"], evidence["approval_error"]) == ("BLOCK", "Denied:GITHUB_HTTP_404")
    assert evidence["baseline_approval"] is None


def test_other_failures_are_recorded_by_type_without_their_text(monkeypatch, tmp_path, candidate):
    # 只有 Denied 帶固定診斷碼；其他例外的文字可能含任意內容。 / Only Denied carries a fixed diagnostic code; other
    # exception text could hold anything.
    import scripts.check_trusted_changes as guard
    (tmp_path / "security").mkdir()
    (tmp_path / "security/trust-policy.json").write_text(json.dumps({**POLICY, "schema_version": 2}))
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    evidence = run_guard_command(monkeypatch, tmp_path, candidate, FakeGitHub(POLICY["repository"]))
    assert (evidence["decision"], evidence["approval_error"]) == ("BLOCK", "ValueError")
