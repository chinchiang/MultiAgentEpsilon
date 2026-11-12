"""信任範圍與 run 可信判斷各只有一份：guard、verifier 與發布程式共用。

The trust scope and the trusted-run rule exist once, shared by the guard, the verifier and the publisher."""
import json
from pathlib import Path

import pytest

from scripts import verify_required_check as verifier
from security_harness import trust_scope, workflow_contract
from security_harness.github_http import Denied
from security_harness.github_trust import trusted_run

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
