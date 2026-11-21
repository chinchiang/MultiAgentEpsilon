"""信任範圍與 run 可信判斷各只有一份：guard、verifier 與發布程式共用。

The trust scope and the trusted-run rule exist once, shared by the guard, the verifier and the publisher."""
import inspect
import json
import re
from pathlib import Path

import pytest

from scripts import verify_required_check as verifier
from security_harness import trust_scope, workflow_contract
from security_harness.github_http import Denied
from security_harness.github_trust import (GitHubTrust, HeadPush, ReviewEvidence, load_trust_policy, load_trust_scope,
                                           parse_time, ruleset_protections, trusted_run)

ROOT = Path(__file__).resolve().parents[1]
HEAD = "b" * 40
RUN = {"repository": {"id": 10, "full_name": "owner/repo"}, "event": "pull_request_target",
       "path": workflow_contract.WORKFLOW_PATH, "workflow_id": 99, "head_sha": HEAD}


def test_scope_comes_from_the_trust_policy_and_the_workflow_contract():
    scope = trust_scope.load(ROOT)
    policy = json.loads((ROOT / "security/trust-policy.json").read_text())
    assert scope == (policy["repository"], workflow_contract.BASE_BRANCH, workflow_contract.WORKFLOW_PATH,
                     workflow_contract.REQUIRED_CHECK)
    assert (verifier.BASE_BRANCH, verifier.WORKFLOW_PATH, verifier.REQUIRED_CHECK) == scope[1:]


@pytest.mark.parametrize("repository", ["", "owner", "owner/repo/extra", "owner/re po", 7])
def test_scope_refuses_a_malformed_trusted_repository(tmp_path, repository):
    (tmp_path / "security").mkdir()
    (tmp_path / "security/trust-policy.json").write_text(json.dumps({"repository": repository}))
    with pytest.raises(ValueError, match="invalid trusted repository"):
        trust_scope.load(tmp_path)


def test_trusted_run_accepts_the_trusted_workflow_run_for_this_head():
    trusted_run(RUN, HEAD, "owner/repo", workflow_contract.WORKFLOW_PATH)
    trusted_run(RUN, HEAD, "owner/repo", workflow_contract.WORKFLOW_PATH, 99)


@pytest.mark.parametrize("change,workflow_id,code", [
    ({"repository": {"id": 99, "full_name": "someone/fork"}}, None, "RUN_REPOSITORY"),
    ({"repository": None}, None, "RUN_REPOSITORY"),
    ({"event": "workflow_dispatch"}, None, "RUN_SOURCE"),
    ({"path": ".github/workflows/copy.yml"}, None, "RUN_SOURCE"),
    ({}, 100, "RUN_SOURCE"),
    ({"head_sha": "d" * 40}, None, "RUN_SHA")])
def test_trusted_run_names_the_check_that_failed(change, workflow_id, code):
    with pytest.raises(Denied, match=f"^{code}$"):
        trusted_run({**RUN, **change}, HEAD, "owner/repo", workflow_contract.WORKFLOW_PATH, workflow_id)


def test_base_branch_name_is_defined_only_in_the_workflow_contract():
    # 分支名稱只在 workflow_contract 定義一次；其他地方寫死 "main" 會在改分支時漏改。 / The branch name is defined once
    # in workflow_contract; a hard-coded "main" elsewhere would be missed when the branch changes.
    default = inspect.signature(GitHubTrust.baseline_approval).parameters['base_branch'].default
    assert default == workflow_contract.BASE_BRANCH
    literal = re.compile(r'''(["'])main\1''')
    holders = sorted(str(p.relative_to(ROOT)) for folder in ('security_harness', 'scripts')
                     for p in (ROOT / folder).rglob('*.py') if literal.search(p.read_text(encoding='utf-8')))
    assert holders == ['security_harness/workflow_contract.py']


def test_trust_policy_and_ruleset_seam_centralized():
    policy = load_trust_policy(ROOT, require_independent_author=True)
    raw = json.loads((ROOT / 'security/trust-policy.json').read_text())
    assert policy.scope == load_trust_scope(ROOT)
    assert policy.baseline_reviewers == raw['baseline_reviewers']
    push = HeadPush(parse_time('2026-11-08T01:00:00Z'), frozenset({'pusher'}))
    evidence = ReviewEvidence(
        [{'id': 9, 'state': 'APPROVED', 'commit_id': HEAD, 'submitted_at': '2026-11-08T01:05:00Z',
          'user': {'login': 'reviewer'}}],
        {'reviewer': 'write'}, {'author'}, push)
    pr = {'draft': False, 'user': {'login': 'author'}, 'head': {'sha': HEAD}}
    assert evidence.decide(pr, ['reviewer']) == [9]
    protections, active, _, _ = ruleset_protections({'protected': False}, [])
    assert not protections['main_protected'] and active == []


def write_policy(root, **overrides):
    policy = {"schema_version": 1, "repository": "owner/repo", "baseline_reviewers": ["reviewer"],
              "require_independent_author": True, **overrides}
    for key in [k for k, v in overrides.items() if v is ...]:
        del policy[key]
    (root / "security").mkdir()
    (root / "security/trust-policy.json").write_text(json.dumps(policy))


UNSUPPORTED = [
    {"schema_version": 2},
    {"schema_version": "1"},
    {"schema_version": ...},
    {"require_independent_author": False},
    {"require_independent_author": "true"},
    {"require_independent_author": 1},
    {"require_independent_author": ...},
]


@pytest.mark.parametrize("overrides", UNSUPPORTED)
def test_strict_policy_refuses_a_schema_or_author_mode_it_does_not_implement(tmp_path, overrides):
    # 此 guard 只實作獨立審查：schema_version 必須恰為 1、require_independent_author 必須恰為 true。 / The guard only
    # implements independent review: schema_version exactly 1 and require_independent_author exactly true.
    write_policy(tmp_path, **overrides)
    with pytest.raises(ValueError, match="^unsupported trust policy$"):
        load_trust_policy(tmp_path, require_independent_author=True)


def test_strict_policy_accepts_the_supported_shape_and_returns_scope_and_reviewers(tmp_path):
    write_policy(tmp_path)
    policy = load_trust_policy(tmp_path, require_independent_author=True)
    assert policy.scope.repository == "owner/repo" and policy.baseline_reviewers == ["reviewer"]


@pytest.mark.parametrize("overrides", UNSUPPORTED)
def test_policy_without_the_strict_flag_does_not_judge_the_author_mode(tmp_path, overrides):
    # 稽核只需要讀取審查者名單，不負責拒絕模式；嚴格檢查由要求它的呼叫端決定。 / The audit only reads the reviewer list;
    # the strict check belongs to the caller that asks for it.
    write_policy(tmp_path, **overrides)
    assert load_trust_policy(tmp_path).baseline_reviewers == ["reviewer"]


def test_the_guard_asks_for_the_strict_policy_before_any_github_read(tmp_path, monkeypatch):
    from scripts import check_trusted_changes as guard
    write_policy(tmp_path, require_independent_author=False)
    monkeypatch.setattr(guard, "ROOT", tmp_path)
    monkeypatch.setattr(guard, "ReadOnlyGitHub", lambda: pytest.fail("the guard read GitHub before refusing the policy"))
    with pytest.raises(ValueError, match="^unsupported trust policy$"):
        guard.live_approval(1, HEAD, "a" * 40)
