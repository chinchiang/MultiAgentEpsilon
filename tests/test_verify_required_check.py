import copy

import pytest

from scripts import verify_required_check as checker

HEAD = "b" * 40


def pull(number=5, base="main", head=HEAD, ref="feature", state="open"):
    return {"number": number, "state": state, "base": {"ref": base, "repo": {"id": 10}},
            "head": {"sha": head, "ref": ref, "repo": {"id": 10}}}


def fake_api(checks, runs_by_suite, pr_state="open"):
    def api(path):
        if path.endswith("/pulls/5"):
            return pull(state=pr_state)
        if "/check-runs?" in path:
            assert f"/commits/{HEAD}/" in path and "filter=all" in path
            return {"total_count": len(checks), "check_runs": checks}
        if "check_suite_id=" in path:
            return {"workflow_runs": runs_by_suite[int(path.split("check_suite_id=")[1].split("&")[0])]}
        raise AssertionError(path)
    return api


def check(id_, suite, conclusion="success", started="2026-10-06T01:00:00Z", app=15368):
    return {"id": id_, "name": "trusted-security-pilot", "app": {"id": app}, "head_sha": HEAD,
            "check_suite": {"id": suite}, "status": "completed", "conclusion": conclusion, "started_at": started}


def run(id_, event="pull_request_target", path=".github/workflows/security.yml", head=HEAD, branch="feature"):
    return {"id": id_, "run_attempt": 1, "event": event, "path": path, "head_sha": head,
            "head_branch": branch, "head_repository": {"id": 10}}


def listing(*extra):
    return lambda path: [pull(), *extra]


def test_trusted_pull_request_target_source_allows():
    result = checker.verify(fake_api([check(1, 10)], {10: [run(100)]}), "owner/repo", 5, listing())
    assert result["decision"] == "ALLOW" and result["sources"][0]["run_id"] == 100


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


def test_closed_pr_is_not_verified():
    with pytest.raises(checker.Denied, match="PR_NOT_OPEN"):
        checker.verify(fake_api([check(1, 10)], {10: [run(100)]}, pr_state="closed"), "owner/repo", 5, listing())


def test_gh_output_is_decoded_as_utf8_not_the_locale_codec(monkeypatch):
    seen = {}
    def fake(args, **kwargs):
        seen.update(kwargs)
        return '{"title": "可信安全閘門"}'
    monkeypatch.setattr(checker.subprocess, "check_output", fake)
    assert checker.gh_api("repos/owner/repo/pulls/6")["title"] == "可信安全閘門"
    assert seen["encoding"] == "utf-8" and "text" not in seen


@pytest.mark.parametrize("twin,branch,code", [
    # Same head opened (then closed) against a branch carrying a modified workflow copy.
    (pull(number=6, base="evil", state="closed"), "feature", "FOREIGN_BASE_PR"),
    (pull(number=6, base="evil", state="open"), "feature", "FOREIGN_BASE_PR"),
    # Twin from another head branch: its run reports that branch, not this PR's.
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
