import copy

import pytest

from scripts import verify_required_check as checker

HEAD = "b" * 40


def pull(number=5, base="main", head=HEAD, ref="feature", state="open"):
    return {"number": number, "state": state, "base": {"ref": base, "repo": {"id": 10}},
            "head": {"sha": head, "ref": ref, "repo": {"id": 10, "full_name": "owner/repo"}}}


def fake_api(checks, runs_by_suite, pr_state="open", jobs=None):
    # 未指定時每筆 check 都是其 run 第 1 次 attempt 的 job。 / Unless given, each check is its run's attempt-1 job.
    if jobs is None:
        jobs = {c["id"]: job(c["id"], runs_by_suite[c["check_suite"]["id"]][0]["id"])
                for c in checks if runs_by_suite.get(c["check_suite"]["id"])}

    def api(path):
        if path.endswith("/pulls/5"):
            return pull(state=pr_state)
        if "/check-runs?" in path:
            assert f"/commits/{HEAD}/" in path and "filter=all" in path
            return {"total_count": len(checks), "check_runs": checks}
        if "check_suite_id=" in path:
            return {"workflow_runs": runs_by_suite[int(path.split("check_suite_id=")[1].split("&")[0])]}
        if "/actions/jobs/" in path:
            return jobs[int(path.rsplit("/", 1)[1])]
        if '/actions/runs/' in path:
            number = int(path.rsplit('/', 1)[1])
            return next(r for runs in runs_by_suite.values() for r in runs if r['id'] == number)
        raise AssertionError(path)
    return api


def check(id_, suite, conclusion="success", started="2026-10-06T01:00:00Z", app=15368):
    return {"id": id_, "name": "trusted-security-pilot", "app": {"id": app}, "head_sha": HEAD,
            "check_suite": {"id": suite}, "status": "completed", "conclusion": conclusion, "started_at": started}


def run(id_, event="pull_request_target", path=".github/workflows/security.yml", head=HEAD, branch="feature",
        attempt=1):
    # GitHub 的 run 只帶目前的 attempt；重跑沿用同一 run 與 check suite。 / A GitHub run carries only its current
    # attempt; a rerun keeps the same run and check suite.
    return {"id": id_, "run_attempt": attempt, "event": event, "path": path, "head_sha": head,
            "head_branch": branch, "head_repository": {"id": 10},
            "status": "completed", "conclusion": "success"}


def job(check_id, run_id, attempt=1, head=HEAD):
    # Actions 的 check run ID 即其 job ID，job 記錄自己所屬的 attempt。 / An Actions check run's ID is its job ID,
    # and the job records the attempt it belongs to.
    return {"id": check_id, "run_id": run_id, "run_attempt": attempt, "head_sha": head,
            "check_run_url": f"https://api.github.com/repos/owner/repo/check-runs/{check_id}"}


def listing(*extra, statuses=()):
    def pages(path):
        if "/timeline?" in path:
            return []
        if path == f"repos/owner/repo/commits/{HEAD}/statuses":
            return list(statuses)
        return [pull(), *extra]
    return pages


def test_trusted_pull_request_target_source_allows():
    result = checker.verify(fake_api([check(1, 10)], {10: [run(100)]}), "owner/repo", 5, listing())
    assert result["decision"] == "ALLOW" and result["sources"][0]["run_id"] == 100


def test_rerun_labels_each_check_with_its_own_attempt():
    # PR #46：attempt 1 失敗、attempt 2 成功，兩者同屬一個 run。 / PR #46: attempt 1 failed and attempt 2 passed
    # within one run.
    checks = [check(1, 10, conclusion="failure"), check(2, 10)]
    jobs = {1: job(1, 100, attempt=1), 2: job(2, 100, attempt=2)}
    result = checker.verify(fake_api(checks, {10: [run(100, attempt=2)]}, jobs=jobs), "owner/repo", 5, listing())
    assert result["decision"] == "ALLOW"
    assert [(s["check_run_id"], s["run_attempt"], s["conclusion"]) for s in result["sources"]] == [
        (1, 1, "failure"), (2, 2, "success")]


def test_latest_check_from_an_older_attempt_cannot_vouch_for_the_run():
    # run 的綠燈屬於 attempt 2，但最新的 check 來自 attempt 1。 / The run's green belongs to attempt 2, but the latest
    # check came from attempt 1.
    api = fake_api([check(1, 10)], {10: [run(100, attempt=2)]}, jobs={1: job(1, 100, attempt=1)})
    with pytest.raises(checker.Denied, match="LATEST_CHECK_STALE_ATTEMPT"):
        checker.verify(api, "owner/repo", 5, listing())


@pytest.mark.parametrize("field,value", [
    ("run_id", 101),
    ("head_sha", "d" * 40),
    ("check_run_url", "https://api.github.com/repos/owner/repo/check-runs/2"),
    ("run_attempt", "1"),
    ("run_attempt", 0),
])
def test_job_that_does_not_match_its_check_leaves_the_attempt_unresolved(field, value):
    record = job(1, 100)
    record[field] = value
    api = fake_api([check(1, 10)], {10: [run(100)]}, jobs={1: record})
    with pytest.raises(checker.Denied, match="CHECK_ATTEMPT_UNRESOLVED"):
        checker.verify(api, "owner/repo", 5, listing())


@pytest.mark.parametrize('status,conclusion', [('completed', 'failure'), ('completed', 'cancelled'),
    ('completed', 'timed_out'), ('in_progress', None), (None, 'success'), ('completed', None)])
def test_green_evaluator_cannot_hide_failed_or_incomplete_signing_workflow(status, conclusion):
    source = run(100)
    source.update(status=status, conclusion=conclusion)
    with pytest.raises(checker.Denied, match='WORKFLOW_NOT_SUCCESS'):
        checker.verify(fake_api([check(1, 10)], {10: [source]}), 'owner/repo', 5, listing())


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
    checks, runs = [check(1, 10)], {10: [run(100)]}
    if attack == "manual_run": runs[10] = [run(100, event="workflow_dispatch")]
    elif attack == "push_run": runs[10] = [run(100, event="push")]
    elif attack == "other_path": runs[10] = [run(100, path=".github/workflows/copy.yml")]
    elif attack == "other_head": runs[10] = [run(100, head="d" * 40)]
    elif attack == "other_app": checks = [check(1, 10, app=999)]
    elif attack == "missing": checks = []
    elif attack == "ambiguous": runs[10] = [run(100), run(101)]
    elif attack == "latest_failed":
        checks = [check(1, 10), check(2, 11, conclusion="failure", started="2026-10-06T02:00:00Z")]
        runs[11] = [run(101)]
    elif attack == "extra_forged_success":
        checks = [check(1, 10), copy.deepcopy(check(2, 11))]
        runs[11] = [run(101, event="push")]
    with pytest.raises(checker.Denied, match=code):
        checker.verify(fake_api(checks, runs), "owner/repo", 5, listing())


def test_queued_rerun_check_is_newer_than_an_earlier_success():
    # 重跑排隊時尚無 started_at；較舊的成功不能代表最新結果。 / A queued rerun has no started_at yet; an older success is not the latest.
    queued = check(2, 11, conclusion=None, started=None)
    queued["status"] = "queued"
    with pytest.raises(checker.Denied, match="LATEST_CHECK_NOT_SUCCESS"):
        checker.verify(fake_api([check(1, 10), queued], {10: [run(100)], 11: [run(101)]}), "owner/repo", 5, listing())


def test_same_named_commit_status_on_the_head_blocks():
    # Actions 權杖可送出同名 status，規則集可能把它當成必要檢查。 / An Actions token can post a same-named status the ruleset may count.
    forged = {"id": 7, "context": "trusted-security-pilot", "state": "success"}
    with pytest.raises(checker.Denied, match="FOREIGN_STATUS_SOURCE"):
        checker.verify(fake_api([check(1, 10)], {10: [run(100)]}), "owner/repo", 5, listing(statuses=[forged]))


def test_closed_pr_is_not_verified():
    with pytest.raises(checker.Denied, match="PR_NOT_OPEN"):
        checker.verify(fake_api([check(1, 10)], {10: [run(100)]}, pr_state="closed"), "owner/repo", 5, listing())


def test_reader_preserves_chinese_titles_without_a_locale_subprocess(monkeypatch):
    class Reader:
        def api(self, path):
            assert path == '/repos/owner/repo/pulls/6'
            return {"title": "可信安全閘門"}
    monkeypatch.setattr(checker, '_reader', Reader())
    assert checker.gh_api("repos/owner/repo/pulls/6")["title"] == "可信安全閘門"


@pytest.mark.parametrize("twin,branch,code", [
    # 相同 head 曾對含修改 workflow 的其他分支開 PR，之後關閉。 / Same head opened (then closed) against a branch carrying a modified workflow copy.
    (pull(number=6, base="evil", state="closed"), "feature", "FOREIGN_BASE_PR"),
    (pull(number=6, base="evil", state="open"), "feature", "FOREIGN_BASE_PR"),
    # 另一 head 分支的雙胞胎 run 回報其分支，不是此 PR 分支。 / Twin from another head branch: its run reports that branch, not this PR's.
    (pull(number=6, base="evil", ref="twin", state="closed"), "twin", "RUN_HEAD_BRANCH"),
])
def test_same_head_pr_into_another_base_cannot_vouch_for_the_check(twin, branch, code):
    with pytest.raises(checker.Denied, match=code):
        checker.verify(fake_api([check(1, 10)], {10: [run(100, branch=branch)]}), "owner/repo", 5, listing(twin))


def test_unrelated_prs_into_other_bases_do_not_block():
    other = pull(number=6, base="release", head="d" * 40, ref="other", state="closed")
    assert checker.verify(fake_api([check(1, 10)], {10: [run(100)]}), "owner/repo", 5, listing(other))["decision"] == "ALLOW"


def test_pr_listing_without_this_pr_fails_closed():
    with pytest.raises(checker.Denied, match="PR_LISTING_INCOMPLETE"):
        checker.verify(fake_api([check(1, 10)], {10: [run(100)]}), "owner/repo", 5, lambda path: [])
