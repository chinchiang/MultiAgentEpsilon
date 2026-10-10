from scripts.check_trusted_changes import protected_changes
from scripts.check_trusted_changes import approved_review
import json
import subprocess
import sys
import pytest
from pathlib import Path


@pytest.fixture(autouse=True)
def clear_ci_run_identity(monkeypatch):
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)


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


@pytest.mark.parametrize("role,approved", [("write", True), ("read", False)])
def test_live_approval_resolves_reviewer_permission_through_github(monkeypatch, role, approved):
    import scripts.check_trusted_changes as guard
    reviewer = json.loads((Path(__file__).resolve().parents[1] / "security/trust-policy.json").read_text())["baseline_reviewers"][-1]
    responses = {
        "pulls/7": {"state": "open", "head": {"sha": "h" * 40}, "base": {"sha": "b" * 40}, "user": {"login": "someone-else"}},
        f"collaborators/{reviewer}/permission": {"role_name": role},
        "commits/" + "h" * 40: {"author": {"login": "someone-else"}, "committer": {"login": "web-flow"}},
    }
    review = {"id": 3, "state": "APPROVED", "commit_id": "h" * 40, "user": {"login": reviewer}}
    commits = [{"sha": "h" * 40, "author": {"login": "someone-else"}, "committer": {"login": "web-flow"}}]
    requested = []
    def fake(args, **kwargs):
        assert kwargs.get("encoding") == "utf-8" and "text" not in kwargs
        path = args[2].split("/", 3)[3]
        requested.append(path)
        if path.startswith("pulls/7/reviews"):
            return json.dumps(review) + "\n"
        if path.startswith("pulls/7/commits"):
            return "".join(json.dumps(c) + "\n" for c in commits)
        return json.dumps(responses[path])
    monkeypatch.setattr(guard.subprocess, "check_output", fake)
    result = guard.live_approval(7, "h" * 40, "b" * 40)
    assert (result is not None) is approved
    assert f"collaborators/{reviewer}/permission" in requested


def test_guard_retains_sha_bound_evidence_even_when_it_blocks(tmp_path):
    repo = tmp_path / "candidate"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    git("init", "-q")
    git("config", "user.name", "Synthetic fixture")
    git("config", "user.email", "fixture@example.invalid")
    (repo / "README.md").write_text("baseline\n")
    git("add", ".")
    git("commit", "-qm", "baseline")
    base = git("rev-parse", "HEAD")
    output = tmp_path / "audit/trusted-guard.json"
    script = Path(__file__).resolve().parents[1] / "scripts/check_trusted_changes.py"
    command = [sys.executable, str(script), "--base", base, "--candidate", str(repo), "--output", str(output)]
    allowed = subprocess.run(command, capture_output=True)
    assert allowed.returncode == 0
    assert json.loads(output.read_text())["decision"] == "ALLOW"
    (repo / "security").mkdir()
    (repo / "security/policy.json").write_text('{}\n')
    git("add", ".")
    git("commit", "-qm", "policy change")
    blocked = subprocess.run(command, capture_output=True)
    evidence = json.loads(output.read_text())
    assert blocked.returncode == 1
    assert evidence["decision"] == "BLOCK"
    assert evidence["base_sha"] == base
    assert evidence["candidate_sha"] == git("rev-parse", "HEAD")
    assert evidence["protected_changes"] == ["security/policy.json"]


@pytest.mark.parametrize("old,new,blocked", [
    ("scripts/evaluator.py", "fixture_app/moved.py", True),
    ("fixture_app/app.py", "scripts/evaluator.py", True),
    ("fixture_app/app.py", "fixture_app/moved.py", True),
])
def test_git_rename_checks_both_sides(tmp_path, old, new, blocked):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], text=True).strip()
    git("init", "-q"); git("config", "user.name", "Synthetic")
    git("config", "user.email", "fixture@example.invalid")
    git("config", "diff.renames", "true")
    source, target = tmp_path / old, tmp_path / new
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("unchanged content\n")
    git("add", "."); git("commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    target.parent.mkdir(parents=True, exist_ok=True)
    git("mv", old, new); git("commit", "-qm", "rename")
    assert git("diff", "--name-status", base, "HEAD").startswith("R100")
    script = Path(__file__).resolve().parents[1] / "scripts/check_trusted_changes.py"
    process = subprocess.run([sys.executable, str(script), "--base", base, "--candidate", str(tmp_path)],
                             capture_output=True, text=True)
    data = json.loads(process.stdout)
    assert process.returncode == int(blocked)
    assert data["decision"] == ("BLOCK" if blocked else "ALLOW")
    assert data["protected_changes"] == protected_changes(sorted([old, new]))


def guard_with_commits(monkeypatch, commits):
    import scripts.check_trusted_changes as guard
    reviewer = json.loads((Path(__file__).resolve().parents[1] / "security/trust-policy.json").read_text())["baseline_reviewers"][-1]
    responses = {
        "pulls/7": {"state": "open", "head": {"sha": "h" * 40}, "base": {"sha": "b" * 40}, "user": {"login": "someone-else"}},
        f"collaborators/{reviewer}/permission": {"role_name": "write"},
        "commits/" + "h" * 40: {"author": {"login": "someone-else"}, "committer": {"login": "web-flow"}},
    }
    review = {"id": 3, "state": "APPROVED", "commit_id": "h" * 40, "user": {"login": reviewer}}
    def fake(args, **kwargs):
        path = args[2].split("/", 3)[3]
        if path.startswith("pulls/7/reviews"):
            return json.dumps(review) + "\n"
        if path.startswith("pulls/7/commits"):
            return "".join(json.dumps(c) + "\n" for c in commits(reviewer))
        return json.dumps(responses[path])
    monkeypatch.setattr(guard.subprocess, "check_output", fake)
    return lambda: guard.live_approval(7, "h" * 40, "b" * 40)


def test_reviewer_who_pushed_an_earlier_pr_commit_cannot_approve(monkeypatch):
    approve = guard_with_commits(monkeypatch, lambda reviewer: [
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
        guard_with_commits(monkeypatch, commits)()


@pytest.mark.parametrize("change", [{"require_independent_author": False}, {"require_independent_author": None},
                                    {"schema_version": 2}])
def test_guard_refuses_trust_policy_it_cannot_enforce(tmp_path, monkeypatch, change):
    import scripts.check_trusted_changes as guard
    policy = json.loads((Path(__file__).resolve().parents[1] / "security/trust-policy.json").read_text())
    (tmp_path / "security").mkdir()
    (tmp_path / "security/trust-policy.json").write_text(json.dumps({**policy, **change}))
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    monkeypatch.setattr(guard.subprocess, "check_output", lambda *a, **k: pytest.fail("GitHub must not be queried"))
    with pytest.raises(ValueError, match="unsupported trust policy"):
        guard.live_approval(7, "h" * 40, "b" * 40)
