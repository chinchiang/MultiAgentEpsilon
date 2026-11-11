"""guard 證據格式只有一份定義：guard 寫入的內容必須正好是自我檢查與發布程式接受的內容。

The guard evidence format has one definition: what the guard writes must be exactly what the self-check and the
publisher accept."""
import json

import pytest

from security_harness import guard_evidence
from security_harness.github_http import Denied
from scripts.check_publishable_evidence import check_guard

BASE, HEAD = "a" * 40, "b" * 40
APPROVAL = {"review_id": 11, "reviewer": "reviewer", "commit_id": HEAD}


def round_trip(evidence):
    """經 JSON 寫出再讀回，與 guard 寫檔、發布程式讀檔相同。 / Through JSON and back, as the guard writes and the
    publisher reads."""
    return json.loads(json.dumps(evidence))


@pytest.mark.parametrize("changes,approval", [([], None), (["security/policy.json"], APPROVAL)])
def test_allowed_guard_evidence_round_trips_through_the_validator(changes, approval):
    evidence = guard_evidence.build(BASE, HEAD, changes, approval, None, None)
    assert evidence["decision"] == "ALLOW"
    assert guard_evidence.validate(round_trip(evidence), BASE, HEAD) == evidence


@pytest.mark.parametrize("changes,approval,error", [
    (["security/policy.json"], None, None), ([], None, "Denied:INDEPENDENT_APPROVAL_MISSING"),
    (["security/policy.json"], APPROVAL, "OSError")])
def test_blocked_guard_evidence_is_never_accepted(changes, approval, error):
    evidence = guard_evidence.build(BASE, HEAD, changes, approval, error, "INDEPENDENT_APPROVAL_MISSING")
    assert evidence["decision"] == "BLOCK"
    with pytest.raises(Denied, match="^TRUSTED_GUARD$"):
        guard_evidence.validate(round_trip(evidence), BASE, HEAD)


def tamper(change):
    evidence = round_trip(guard_evidence.build(BASE, HEAD, ["security/policy.json"], APPROVAL, None, None))
    change(evidence)
    return evidence


@pytest.mark.parametrize("change", [
    lambda d: d.pop("policy"), lambda d: d.update(extra=1), lambda d: d.update(schema_version=3),
    lambda d: d.update(schema_version=True), lambda d: d.update(policy="other"), lambda d: d.update(base_sha="c" * 40),
    lambda d: d.update(candidate_sha="c" * 40), lambda d: d.update(approval_refusal=7),
    lambda d: d.update(protected_changes="security/policy.json"), lambda d: d.update(protected_changes=[""]),
    lambda d: d.update(baseline_approval=None), lambda d: d["baseline_approval"].update(commit_id="c" * 40),
    lambda d: d["baseline_approval"].update(review_id=0), lambda d: d["baseline_approval"].update(review_id="11"),
    lambda d: d["baseline_approval"].update(reviewer=""), lambda d: d["baseline_approval"].pop("reviewer"),
    lambda d: d["baseline_approval"].update(extra=1)],
    ids=["missing-field", "extra-field", "schema-bump", "schema-bool", "policy", "base", "head", "refusal-type",
         "changes-type", "empty-change", "no-approval", "approval-head", "review-id-zero", "review-id-text",
         "empty-reviewer", "missing-reviewer", "extra-approval-field"])
def test_any_other_guard_shape_is_refused(change):
    with pytest.raises(Denied, match="^TRUSTED_GUARD$"):
        guard_evidence.validate(tamper(change), BASE, HEAD)


def test_non_object_guard_is_refused():
    with pytest.raises(Denied, match="^TRUSTED_GUARD$"):
        guard_evidence.validate([], BASE, HEAD)


def provenance(pr_number):
    return {"pr_number": pr_number, "base_sha": BASE, "candidate_sha": HEAD}


def test_self_check_requires_valid_guard_evidence_only_on_pull_request_runs():
    valid = json.dumps(guard_evidence.build(BASE, HEAD, ["security/policy.json"], APPROVAL, None, None)).encode()
    check_guard({"audit/trusted-guard.json": valid}, provenance(7))
    check_guard({}, provenance(0))
    with pytest.raises(Denied, match="^EVIDENCE_FILE_MISSING$"):
        check_guard({}, provenance(7))
    with pytest.raises(Denied, match="^TRUSTED_GUARD$"):
        check_guard({"audit/trusted-guard.json": valid}, provenance(0))
    stale = json.dumps(guard_evidence.build("c" * 40, HEAD, [], None, None, None)).encode()
    with pytest.raises(Denied, match="^TRUSTED_GUARD$"):
        check_guard({"audit/trusted-guard.json": stale}, provenance(7))
