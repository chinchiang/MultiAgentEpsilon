import json

import pytest

from scripts import verify_required_check as checker
from security_harness.github_readonly import GitHubReader
from tests.fake_github import FakeGitHub

HEAD = "b" * 40


def pull(number=5, base="main", head=HEAD, ref="feature", state="open"):
    return {"number": number, "state": state, "base": {"ref": base, "repo": {"id": 10}},
            "head": {"sha": head, "ref": ref, "repo": {"id": 10, "full_name": "owner/repo"}}}


def scenario(*twins, pr_state="open", statuses=()):
    # PR 5 的 head 上尚無 check；twins 是同一 head 查詢會列出的其他 PR。 / PR 5 with no checks on its head yet; twins
    # are the other PRs the same-head query lists.
    github = FakeGitHub("owner/repo")
    github.add("pulls/5", pull(state=pr_state))
    github.add(f"commits/{HEAD}/statuses", list(statuses))
    github.check_runs(HEAD, checker.REQUIRED_CHECK)
    related = [pull(), *twins]
    github.add("pulls?state=all&head=owner:feature", related)
    for p in related:
        github.add(f"issues/{p['number']}/timeline", [])
    return github


def trusted_run(github, run_id=100, suite=10, **fields):
    trusted = {"event": "pull_request_target", "path": checker.WORKFLOW_PATH, "head_branch": "feature",
               "head_repository": {"id": 10}}
    return github.workflow_run(run_id, HEAD, suite, **{**trusted, **fields})


def evaluate(github, run, conclusion="success"):
    return github.attempt(run, conclusion=conclusion, name=checker.REQUIRED_CHECK)


def verify(github):
    return checker.verify(GitHubReader(github, "owner/repo"), 5)


def test_trusted_pull_request_target_source_allows():
    github = scenario()
    evaluate(github, trusted_run(github))
    result = verify(github)
    assert result["decision"] == "ALLOW" and [s["run_id"] for s in result["sources"]] == [100]


def test_rerun_labels_each_check_with_its_own_attempt():
    # PR #46 實際發生：attempt 1 失敗、attempt 2 成功，兩者同屬一個 run（#48 修正）。 / Seen on PR #46: attempt 1 failed
    # and attempt 2 passed within one run (fixed in #48).
    github = scenario()
    run = trusted_run(github)
    first, second = evaluate(github, run, "failure"), evaluate(github, run)
    result = verify(github)
    assert result["decision"] == "ALLOW"
    assert [(s["check_run_id"], s["run_attempt"], s["conclusion"]) for s in result["sources"]] == [
        (first["id"], 1, "failure"), (second["id"], 2, "success")]


def test_latest_check_from_an_older_attempt_cannot_vouch_for_the_run():
    # run 的綠燈屬於 attempt 2，但最新的 check 來自 attempt 1。 / The run's green belongs to attempt 2, but the latest
    # check came from attempt 1.
    github = scenario()
    run = trusted_run(github)
    evaluate(github, run)
    run["run_attempt"] = 2
    with pytest.raises(checker.Denied, match="^LATEST_CHECK_STALE_ATTEMPT$"):
        verify(github)


def test_job_that_does_not_match_its_check_leaves_the_attempt_unresolved():
    github = scenario()
    check = evaluate(github, trusted_run(github))
    github.job(check["id"])["run_id"] = 101
    with pytest.raises(checker.Denied, match="^CHECK_ATTEMPT_UNRESOLVED$"):
        verify(github)


def test_check_run_listing_whose_total_disagrees_fails_closed():
    github = scenario()
    evaluate(github, trusted_run(github))
    github.check_runs(HEAD, checker.REQUIRED_CHECK).total_count = 2
    with pytest.raises(checker.Denied, match="^LISTING_TOTAL$"):
        verify(github)


@pytest.mark.parametrize('status,conclusion', [('completed', 'failure'), ('completed', 'cancelled'),
    ('completed', 'timed_out'), ('in_progress', None), (None, 'success'), ('completed', None)])
def test_green_evaluator_cannot_hide_failed_or_incomplete_signing_workflow(status, conclusion):
    github = scenario()
    run = trusted_run(github)
    evaluate(github, run)
    run.update(status=status, conclusion=conclusion)
    with pytest.raises(checker.Denied, match='^WORKFLOW_NOT_SUCCESS$'):
        verify(github)


@pytest.mark.parametrize("attack,code", [
    ("manual_run", "UNTRUSTED_CHECK_SOURCE"),
    ("push_run", "UNTRUSTED_CHECK_SOURCE"),
    ("other_path", "UNTRUSTED_CHECK_SOURCE"),
    ("other_head", "UNTRUSTED_CHECK_SOURCE"),
    ("other_app", "FOREIGN_CHECK_SOURCE"),
    ("missing", "REQUIRED_CHECK_MISSING"),
    ("ambiguous", "CHECK_RUN_SOURCE_AMBIGUOUS"),
    ("latest_failed", "LATEST_CHECK_NOT_SUCCESS"),
    ("extra_forged_success", "UNTRUSTED_CHECK_SOURCE"),
])
def test_forged_or_manual_sources_block(attack, code):
    github = scenario()
    if attack == "manual_run": evaluate(github, trusted_run(github, event="workflow_dispatch"))
    elif attack == "push_run": evaluate(github, trusted_run(github, event="push"))
    elif attack == "other_path": evaluate(github, trusted_run(github, path=".github/workflows/copy.yml"))
    elif attack == "other_head":
        run = trusted_run(github)
        evaluate(github, run)
        run["head_sha"] = "d" * 40
    elif attack == "other_app": evaluate(github, trusted_run(github))["app"]["id"] = 999
    elif attack == "ambiguous":
        evaluate(github, trusted_run(github))
        trusted_run(github, 101, suite=10)
    elif attack == "latest_failed":
        evaluate(github, trusted_run(github))
        evaluate(github, trusted_run(github, 101, suite=11), "failure")
    elif attack == "extra_forged_success":
        evaluate(github, trusted_run(github))
        evaluate(github, trusted_run(github, 101, suite=11, event="push"))
    with pytest.raises(checker.Denied, match=f"^{code}$"):
        verify(github)


def test_queued_rerun_check_is_newer_than_an_earlier_success():
    # 重跑排隊時尚無 started_at；較舊的成功不能代表最新結果。 / A queued rerun has no started_at yet; an older success is not the latest.
    github = scenario()
    evaluate(github, trusted_run(github))
    queued = evaluate(github, trusted_run(github, 101, suite=11))
    queued.update(status="queued", conclusion=None)
    with pytest.raises(checker.Denied, match="^LATEST_CHECK_NOT_SUCCESS$"):
        verify(github)


def test_same_named_commit_status_on_the_head_blocks():
    # Actions 權杖可送出同名 status，規則集可能把它當成必要檢查。 / An Actions token can post a same-named status the ruleset may count.
    github = scenario(statuses=[{"id": 7, "context": checker.REQUIRED_CHECK, "state": "success"}])
    evaluate(github, trusted_run(github))
    with pytest.raises(checker.Denied, match="^FOREIGN_STATUS_SOURCE$"):
        verify(github)


def test_closed_pr_is_not_verified():
    github = scenario(pr_state="closed")
    evaluate(github, trusted_run(github))
    with pytest.raises(checker.Denied, match="^PR_NOT_OPEN$"):
        verify(github)


@pytest.mark.parametrize("twin,branch,code", [
    # 相同 head 曾對含修改 workflow 的其他分支開 PR，之後關閉。 / Same head opened (then closed) against a branch carrying a modified workflow copy.
    (pull(number=6, base="evil", state="closed"), "feature", "FOREIGN_BASE_PR"),
    (pull(number=6, base="evil", state="open"), "feature", "FOREIGN_BASE_PR"),
    # 另一 head 分支的雙胞胎 run 回報其分支，不是此 PR 分支。 / Twin from another head branch: its run reports that branch, not this PR's.
    (pull(number=6, base="evil", ref="twin", state="closed"), "twin", "RUN_HEAD_BRANCH"),
])
def test_same_head_pr_into_another_base_cannot_vouch_for_the_check(twin, branch, code):
    github = scenario(twin)
    evaluate(github, trusted_run(github, head_branch=branch))
    with pytest.raises(checker.Denied, match=f"^{code}$"):
        verify(github)


def test_unrelated_prs_into_other_bases_do_not_block():
    github = scenario(pull(number=6, base="release", head="d" * 40, ref="other", state="closed"))
    evaluate(github, trusted_run(github))
    assert verify(github)["decision"] == "ALLOW"


def test_pr_listing_without_this_pr_fails_closed():
    github = scenario()
    evaluate(github, trusted_run(github))
    github.add("pulls?state=all&head=owner:feature", [])
    with pytest.raises(checker.Denied, match="^PR_LISTING_INCOMPLETE$"):
        verify(github)


def test_command_reads_through_the_read_only_client(monkeypatch, capsys):
    # 指令只經唯讀 client 讀取，不啟動依賴 locale 的子程序。 / The command reads only through the read-only client,
    # never a locale-dependent subprocess.
    github = scenario()
    evaluate(github, trusted_run(github))
    monkeypatch.setattr(checker, "ReadOnlyGitHub", lambda: github)
    monkeypatch.setattr("sys.argv", ["verify_required_check.py", "--repo", "owner/repo", "--pr", "5"])
    assert checker.main() == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "ALLOW"
    assert {method for method, _, _ in github.requests} == {"GET"}
